package sshd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/marstack-labs/marstack-access/internal/dataplane/certs"
	"github.com/marstack-labs/marstack-access/internal/kernel/audit"
	"github.com/marstack-labs/marstack-access/internal/kernel/authz"
	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
	"github.com/marstack-labs/marstack-access/internal/kernel/logging"
)

const (
	dbTargetID = "tgt-0000000000001"
	aliceID    = "usr-0000000000001"
)

var alice = authz.Identity{
	UserID:       aliceID,
	Name:         "alice",
	Role:         authz.RoleOperator,
	CredentialID: "key-0000000000001",
}

type stubs struct {
	identities   map[string]authz.Identity
	targets      map[string]Target
	policyDenied bool
	grantDenied  bool

	mu        sync.Mutex
	opened    []SessionOpened
	closed    map[string]SessionClosed
	openFails bool
}

func (s *stubs) Open(_ context.Context, rec SessionOpened) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.openFails {
		return fault.Unavailable("store_down", "the session store is unreachable")
	}
	s.opened = append(s.opened, rec)
	return nil
}

func (s *stubs) Close(_ context.Context, id string, rec SessionClosed) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed == nil {
		s.closed = map[string]SessionClosed{}
	}
	s.closed[id] = rec
	return nil
}

func (s *stubs) records() ([]SessionOpened, map[string]SessionClosed) {
	s.mu.Lock()
	defer s.mu.Unlock()

	snapshot := map[string]SessionClosed{}
	for id, rec := range s.closed {
		snapshot[id] = rec
	}
	return append([]SessionOpened{}, s.opened...), snapshot
}

func newStubs() *stubs {
	return &stubs{
		identities: map[string]authz.Identity{},
		targets: map[string]Target{
			"db-1": {
				ID: dbTargetID, Name: "db-1", Address: "10.0.0.4", Port: 22,
				Principals: []string{"deploy", "postgres"},
				HostKey:    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPRgofQjYk3eRPaZxnxDvFK/9Dp87Ki7q596HY3FO2SA",
			},
		},
	}
}

func (s *stubs) ByPublicKey(_ context.Context, fingerprint string) (authz.Identity, error) {
	id, ok := s.identities[fingerprint]
	if !ok {
		return authz.Identity{}, fault.Unauthenticated("unknown_key", "that public key is not registered")
	}
	return id, nil
}

func (s *stubs) lookup(_ context.Context, name string) (Target, error) {
	t, ok := s.targets[name]
	if !ok {
		return Target{}, fault.NotFound("target_not_found", "no target with that name is registered")
	}
	return t, nil
}

func (s *stubs) Authorize(context.Context, authz.Identity, string, string) error {
	if s.policyDenied {
		return fault.Forbidden("no_policy", "no policy grants this principal on this target")
	}
	return nil
}

func (s *stubs) HasGrant(context.Context, string, string, string) error {
	if s.grantDenied {
		return fault.Forbidden("no_grant", "no approved and unexpired request grants this")
	}
	return nil
}

func newKeyPair(t *testing.T) ssh.Signer {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer
}

func startServer(t *testing.T, st *stubs) (*Server, string) {
	t.Helper()

	return startServerWith(t, st, nil, t.TempDir())
}

func startServerWith(t *testing.T, st *stubs, signer certs.Signer, dataDir string) (*Server, string) {
	t.Helper()

	sink, err := audit.OpenFileSink(filepath.Join(dataDir, "audit"))
	if err != nil {
		t.Fatalf("open audit sink: %v", err)
	}
	t.Cleanup(func() { sink.Close() })
	trail := audit.New(logging.New("error", io.Discard), sink, nil)
	t.Cleanup(func() { trail.Close() })

	srv, err := New(Config{Listen: "127.0.0.1:0", DataDir: dataDir, AdvertiseIP: "127.0.0.1"},
		logging.New("error", io.Discard), st, st.lookup, st, st, signer, st.Open, st.Close, trail)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	srv.auditPath = sink.Path()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		listener.Close()
	})

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go srv.handle(ctx, conn)
		}
	}()

	return srv, listener.Addr().String()
}

type dialResult struct {
	stdout string
	stderr string
	err    error
}

func dial(t *testing.T, srv *Server, addr, user string, signer ssh.Signer) dialResult {
	t.Helper()

	hostKey, _, _, _, err := ssh.ParseAuthorizedKey(ssh.MarshalAuthorizedKey(srv.hostKey))
	if err != nil {
		t.Fatalf("parse host key: %v", err)
	}

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		return dialResult{err: err}
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return dialResult{err: err}
	}
	defer session.Close()

	var stdout, stderr strings.Builder
	session.Stdout = &stdout
	session.Stderr = &stderr

	runErr := session.Shell()
	if runErr == nil {
		runErr = session.Wait()
	}

	return dialResult{stdout: stdout.String(), stderr: stderr.String(), err: runErr}
}

func registeredAlice(t *testing.T) (*stubs, ssh.Signer) {
	t.Helper()

	st := newStubs()
	signer := newKeyPair(t)
	st.identities[ssh.FingerprintSHA256(signer.PublicKey())] = alice
	return st, signer
}

func TestASessionWithNoSignerCannotConnect(t *testing.T) {
	st, signer := registeredAlice(t)
	srv, addr := startServer(t, st)

	res := dial(t, srv, addr, "deploy:db-1", signer)

	if res.err == nil {
		t.Fatal("a session opened with no signing authority configured")
	}
	if !strings.Contains(res.stderr, "no signing authority") {
		t.Fatalf("stderr = %q, want it to name the missing signer", res.stderr)
	}
}

func TestAnUnregisteredKeyCannotEvenConnect(t *testing.T) {
	st, _ := registeredAlice(t)
	srv, addr := startServer(t, st)

	res := dial(t, srv, addr, "deploy:db-1", newKeyPair(t))

	if res.err == nil {
		t.Fatal("a key nobody registered completed the handshake")
	}
	if strings.Contains(res.err.Error(), "db-1") || strings.Contains(res.err.Error(), "alice") {
		t.Fatalf("the handshake error names inventory: %v", res.err)
	}
}

func TestAuthorizationFailuresExplainThemselvesToAnAuthenticatedUser(t *testing.T) {
	cases := map[string]struct {
		user    string
		arrange func(*stubs)
		expect  string
	}{
		"no colon":              {user: "db-1", expect: "deploy:db-1"},
		"unknown target":        {user: "deploy:ghost", expect: "no target with that name"},
		"principal not on host": {user: "root:db-1", expect: "does not accept the principal"},
		"policy refuses": {
			user:    "deploy:db-1",
			arrange: func(s *stubs) { s.policyDenied = true },
			expect:  "no policy grants",
		},
		"no grant": {
			user:    "deploy:db-1",
			arrange: func(s *stubs) { s.grantDenied = true },
			expect:  "no approved and unexpired request",
		},
	}

	for label, c := range cases {
		st, signer := registeredAlice(t)
		if c.arrange != nil {
			c.arrange(st)
		}
		srv, addr := startServer(t, st)

		res := dial(t, srv, addr, c.user, signer)

		if res.err == nil {
			t.Errorf("%s: the session succeeded", label)
			continue
		}
		if !strings.Contains(res.stderr, c.expect) {
			t.Errorf("%s: stderr = %q, want it to contain %q. A caller who has proved who they are gains nothing from a blank refusal",
				label, res.stderr, c.expect)
		}
		if !strings.Contains(res.stderr, "refused") {
			t.Errorf("%s: stderr does not say the session was refused: %q", label, res.stderr)
		}
	}
}

func TestLocalPortForwardingIsRefused(t *testing.T) {
	st, signer := registeredAlice(t)
	srv, addr := startServer(t, st)

	hostKey, _, _, _, err := ssh.ParseAuthorizedKey(ssh.MarshalAuthorizedKey(srv.hostKey))
	if err != nil {
		t.Fatalf("parse host key: %v", err)
	}

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "deploy:db-1",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	if conn, err := client.Dial("tcp", "10.0.0.9:5432"); err == nil {
		conn.Close()
		t.Fatal("ssh -L opened a tunnel. A gateway that forwards ports is a route out of the network that no policy describes")
	}
}

func TestRemotePortForwardingIsRefused(t *testing.T) {
	st, signer := registeredAlice(t)
	srv, addr := startServer(t, st)

	hostKey, _, _, _, err := ssh.ParseAuthorizedKey(ssh.MarshalAuthorizedKey(srv.hostKey))
	if err != nil {
		t.Fatalf("parse host key: %v", err)
	}

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "deploy:db-1",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	if listener, err := client.Listen("tcp", "127.0.0.1:0"); err == nil {
		listener.Close()
		t.Fatal("ssh -R opened a reverse tunnel")
	}
}

func TestOnlySessionChannelsAreAccepted(t *testing.T) {
	st, signer := registeredAlice(t)
	srv, addr := startServer(t, st)

	hostKey, _, _, _, err := ssh.ParseAuthorizedKey(ssh.MarshalAuthorizedKey(srv.hostKey))
	if err != nil {
		t.Fatalf("parse host key: %v", err)
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	client, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:            "deploy:db-1",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
	})
	if err != nil {
		t.Fatalf("client conn: %v", err)
	}
	defer client.Close()
	go ssh.DiscardRequests(reqs)
	go func() {
		for ch := range chans {
			ch.Reject(ssh.Prohibited, "")
		}
	}()

	if _, _, err := client.OpenChannel("marac-smuggle", nil); err == nil {
		t.Fatal("an unknown channel type was accepted")
	}
}

func TestTheHostKeyIsStableAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	st := newStubs()

	first, err := New(Config{Listen: "127.0.0.1:0", DataDir: dir},
		logging.New("error", io.Discard), st, st.lookup, st, st, nil, st.Open, st.Close, nil)
	if err != nil {
		t.Fatalf("first: %v", err)
	}

	second, err := New(Config{Listen: "127.0.0.1:0", DataDir: dir},
		logging.New("error", io.Discard), st, st.lookup, st, st, nil, st.Open, st.Close, nil)
	if err != nil {
		t.Fatalf("second: %v", err)
	}

	if first.HostKeyFingerprint() != second.HostKeyFingerprint() {
		t.Fatal("the host key changed on restart, so every client would report a changed key and learn to ignore the warning")
	}
}

func TestTheHostKeyIsNotWorldReadable(t *testing.T) {
	dir := t.TempDir()
	st := newStubs()

	if _, err := New(Config{Listen: "127.0.0.1:0", DataDir: dir},
		logging.New("error", io.Discard), st, st.lookup, st, st, nil, st.Open, st.Close, nil); err != nil {
		t.Fatalf("new: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, hostKeyFile))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %#o, want 0600: this key is what proves the gateway is the gateway", perm)
	}
}

func TestACorruptHostKeyFailsRatherThanBeingReplaced(t *testing.T) {
	dir := t.TempDir()
	st := newStubs()

	if err := os.WriteFile(filepath.Join(dir, hostKeyFile), []byte("not a key\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, err := New(Config{Listen: "127.0.0.1:0", DataDir: dir},
		logging.New("error", io.Discard), st, st.lookup, st, st, nil, st.Open, st.Close, nil); err == nil {
		t.Fatal("a corrupt host key was silently replaced. Generating a new one would make every client's stored key wrong at once, which is indistinguishable from an attack")
	}
}

func TestParseDestination(t *testing.T) {
	valid := map[string]destination{
		"deploy:db-1":     {principal: "deploy", target: "db-1"},
		"_svc:web-01":     {principal: "_svc", target: "web-01"},
		"root:a":          {principal: "root", target: "a"},
		"app-runner:db-1": {principal: "app-runner", target: "db-1"},
	}
	for user, want := range valid {
		got, err := parseDestination(user)
		if err != nil {
			t.Errorf("parseDestination(%q) = %v, want %+v", user, err, want)
			continue
		}
		if got != want {
			t.Errorf("parseDestination(%q) = %+v, want %+v", user, got, want)
		}
	}

	invalid := []string{
		"",
		"db-1",
		"deploy:",
		":db-1",
		"deploy:db-1:extra",
		"deploy:DB-1",
		"Deploy:db-1",
		"deploy db-1",
		"deploy:db_1",
		"deploy:../etc",
		"deploy:db-1 -oProxyCommand=id",
	}
	for _, user := range invalid {
		if got, err := parseDestination(user); err == nil {
			t.Errorf("parseDestination(%q) = %+v, want an error", user, got)
		}
	}
}

func TestAgentForwardingAndSubsystemsAreRefused(t *testing.T) {
	st, signer := registeredAlice(t)
	srv, addr := startServer(t, st)

	hostKey, _, _, _, err := ssh.ParseAuthorizedKey(ssh.MarshalAuthorizedKey(srv.hostKey))
	if err != nil {
		t.Fatalf("parse host key: %v", err)
	}

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "deploy:db-1",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	for _, request := range []string{"auth-agent-req@openssh.com", "x11-req", "subsystem"} {
		session, err := client.NewSession()
		if err != nil {
			t.Fatalf("%s: new session: %v", request, err)
		}

		ok, err := session.SendRequest(request, true, nil)
		if err != nil {
			t.Errorf("%s: send request: %v", request, err)
		}
		if ok {
			t.Errorf("%s was accepted. Each of these hands the session a capability, and an agent socket in particular lets a compromised host reuse the user's other keys", request)
		}
		session.Close()
	}
}

func TestASessionThatNeverStartsIsNotLeftOpen(t *testing.T) {
	st, signer := registeredAlice(t)
	srv, addr := startServer(t, st)

	hostKey, _, _, _, err := ssh.ParseAuthorizedKey(ssh.MarshalAuthorizedKey(srv.hostKey))
	if err != nil {
		t.Fatalf("parse host key: %v", err)
	}

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "deploy:db-1",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer session.Close()

	if err := session.Setenv("MARAC", "1"); err != nil {
		t.Fatalf("env request was refused, so a plain ssh client would fail before reaching a shell: %v", err)
	}
}

func TestATargetWithNoPinnedHostKeyIsRefused(t *testing.T) {
	st, signer := registeredAlice(t)
	unpinned := st.targets["db-1"]
	unpinned.HostKey = ""
	st.targets["db-1"] = unpinned

	srv, addr := startServer(t, st)

	res := dial(t, srv, addr, "deploy:db-1", signer)

	if res.err == nil {
		t.Fatal("a session opened against a host whose identity has never been verified")
	}
	if !strings.Contains(res.stderr, "no pinned host key") {
		t.Fatalf("stderr = %q, want it to name the missing pin", res.stderr)
	}
}

func withRealTarget(t *testing.T) (*Server, string, ssh.Signer, *fakeTarget, string) {
	t.Helper()

	ca := newTestCA(t)
	target := startFakeTarget(t, ca)

	st, clientKey := registeredAlice(t)
	st.targets["db-1"] = fakeTargetEntry(t, target)

	dataDir := t.TempDir()
	srv, addr := startServerWith(t, st, ca, dataDir)
	return srv, addr, clientKey, target, dataDir
}

func TestASessionReachesTheTargetAndCarriesItsOutput(t *testing.T) {
	srv, addr, clientKey, target, _ := withRealTarget(t)

	res := dial(t, srv, addr, "deploy:db-1", clientKey)
	if res.err != nil {
		t.Fatalf("session failed: %v (stderr: %s)", res.err, res.stderr)
	}

	if !strings.Contains(res.stdout, "welcome to db-1") {
		t.Fatalf("stdout = %q, want the target's own banner", res.stdout)
	}

	users, certificates, sessions := target.seen()
	if sessions != 1 {
		t.Fatalf("the target saw %d sessions, want 1", sessions)
	}
	if len(users) != 1 || users[0] != "deploy" {
		t.Fatalf("the target saw users %v, want [deploy]", users)
	}
	if len(certificates) != 1 || certificates[0] == nil {
		t.Fatal("the target did not authenticate a certificate")
	}
}

func TestTheCertificateTheTargetSeesIsScopedToTheSession(t *testing.T) {
	srv, addr, clientKey, target, _ := withRealTarget(t)

	if res := dial(t, srv, addr, "deploy:db-1", clientKey); res.err != nil {
		t.Fatalf("session failed: %v (%s)", res.err, res.stderr)
	}

	_, certificates, _ := target.seen()
	cert := certificates[0]

	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "deploy" {
		t.Errorf("principals = %v, want [deploy]", cert.ValidPrincipals)
	}
	if !strings.HasPrefix(cert.KeyId, "ses-") {
		t.Errorf("key id = %q, want a session id so the target's own logs name the session", cert.KeyId)
	}
	if got := cert.Permissions.CriticalOptions["source-address"]; got != "127.0.0.1/32" {
		t.Errorf("source-address = %q, want the gateway pinned to a single host", got)
	}
	if _, present := cert.Permissions.Extensions["permit-port-forwarding"]; present {
		t.Error("the certificate the target accepted grants port forwarding")
	}
	if window := cert.ValidBefore - cert.ValidAfter; window > uint64((certLifetime + clockSkew).Seconds()) {
		t.Errorf("validity window = %d seconds, want at most %v", window, certLifetime+clockSkew)
	}
}

func TestTheUserNeverReceivesTheCertificate(t *testing.T) {
	srv, addr, clientKey, target, _ := withRealTarget(t)

	res := dial(t, srv, addr, "deploy:db-1", clientKey)
	if res.err != nil {
		t.Fatalf("session failed: %v", res.err)
	}

	_, certificates, _ := target.seen()
	marshalled := string(ssh.MarshalAuthorizedKey(certificates[0]))

	for _, stream := range []string{res.stdout, res.stderr} {
		if strings.Contains(stream, "cert-v01") || strings.Contains(stream, marshalled) {
			t.Fatal("the session wrote the certificate to the user. If a user held a usable certificate they could ssh straight to the target and leave no recording")
		}
	}
}

func TestTheSessionIsRecordedAsAsciicast(t *testing.T) {
	srv, addr, clientKey, _, dataDir := withRealTarget(t)

	if res := dial(t, srv, addr, "deploy:db-1", clientKey); res.err != nil {
		t.Fatalf("session failed: %v (%s)", res.err, res.stderr)
	}

	entries, err := os.ReadDir(filepath.Join(dataDir, recordingDir))
	if err != nil {
		t.Fatalf("read recordings: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("%d recordings written, want 1", len(entries))
	}
	if !strings.HasSuffix(entries[0].Name(), ".cast") {
		t.Errorf("recording name = %q, want a .cast suffix", entries[0].Name())
	}

	path := filepath.Join(dataDir, recordingDir, entries[0].Name())
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read recording: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) < 2 {
		t.Fatalf("recording has %d lines, want a header and at least one event: %s", len(lines), raw)
	}

	var head header
	if err := json.Unmarshal([]byte(lines[0]), &head); err != nil {
		t.Fatalf("header is not JSON: %v (%s)", err, lines[0])
	}
	if head.Version != 2 {
		t.Errorf("version = %d, want 2", head.Version)
	}
	if head.Width == 0 || head.Height == 0 {
		t.Errorf("header = %+v, want terminal dimensions", head)
	}
	if head.Timestamp == 0 {
		t.Error("header carries no timestamp")
	}

	var event []any
	if err := json.Unmarshal([]byte(lines[1]), &event); err != nil {
		t.Fatalf("event is not JSON: %v (%s)", err, lines[1])
	}
	if len(event) != 3 || event[1] != "o" {
		t.Fatalf("event = %v, want [elapsed, \"o\", data]", event)
	}
	if data, _ := event[2].(string); !strings.Contains(data, "welcome to db-1") {
		t.Fatalf("the first event does not carry the target's output: %v", event)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != recordingPerm {
		t.Fatalf("recording mode = %#o, want %#o", perm, recordingPerm)
	}
}

func TestWhatTheUserTypesIsRecordedOnlyBecauseTheTargetEchoesIt(t *testing.T) {
	srv, addr, clientKey, _, dataDir := withRealTarget(t)

	hostKey, _, _, _, err := ssh.ParseAuthorizedKey(ssh.MarshalAuthorizedKey(srv.hostKey))
	if err != nil {
		t.Fatalf("parse host key: %v", err)
	}

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "deploy:db-1",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientKey)},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatalf("stdin: %v", err)
	}
	var stdout strings.Builder
	session.Stdout = &stdout

	if err := session.Shell(); err != nil {
		t.Fatalf("shell: %v", err)
	}
	if _, err := io.WriteString(stdin, "uptime\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	stdin.Close()
	_ = session.Wait()

	entries, err := os.ReadDir(filepath.Join(dataDir, recordingDir))
	if err != nil {
		t.Fatalf("read recordings: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dataDir, recordingDir, entries[0].Name()))
	if err != nil {
		t.Fatalf("read recording: %v", err)
	}

	if !strings.Contains(string(raw), "uptime") {
		t.Fatal("the echoed command is missing from the recording, so shell activity would not be greppable")
	}

	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n")[1:] {
		var event []any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("event is not JSON: %v", err)
		}
		if event[1] == "i" {
			t.Fatal(`the recording carries an "i" input event. Recording only output means a password typed at a sudo prompt is never written down, because the target does not echo it`)
		}
	}
}

func TestARecordingThatCannotBeOpenedRefusesTheSession(t *testing.T) {
	ca := newTestCA(t)
	target := startFakeTarget(t, ca)

	st, clientKey := registeredAlice(t)
	st.targets["db-1"] = fakeTargetEntry(t, target)

	dataDir := t.TempDir()
	blocked := filepath.Join(dataDir, recordingDir)
	if err := os.WriteFile(blocked, []byte("not a directory\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	srv, addr := startServerWith(t, st, ca, dataDir)

	res := dial(t, srv, addr, "deploy:db-1", clientKey)

	if res.err == nil {
		t.Fatal("a session opened even though it could not be recorded")
	}
	if !strings.Contains(res.stderr, "cannot be recorded") {
		t.Fatalf("stderr = %q, want it to say the session cannot be recorded", res.stderr)
	}
	if users, _, _ := target.seen(); len(users) != 0 {
		t.Fatalf("the target authenticated %d times before the recorder was open. Counting shells would miss this: the handshake and the certificate check already happened, and the target's own auth log would show a login that this platform has no recording of",
			len(users))
	}
}

func TestAHostKeyThatDoesNotMatchThePinIsRefused(t *testing.T) {
	ca := newTestCA(t)
	target := startFakeTarget(t, ca)

	st, clientKey := registeredAlice(t)
	entry := fakeTargetEntry(t, target)
	entry.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(newKeyPair(t).PublicKey())))
	st.targets["db-1"] = entry

	srv, addr := startServerWith(t, st, ca, t.TempDir())

	res := dial(t, srv, addr, "deploy:db-1", clientKey)

	if res.err == nil {
		t.Fatal("the gateway connected to a host whose key does not match the pin")
	}
	if !strings.Contains(res.stderr, "could not open a session") {
		t.Fatalf("stderr = %q, want a dial failure", res.stderr)
	}
}

func TestATargetThatDistrustsOurCARefusesTheSession(t *testing.T) {
	ours := newTestCA(t)
	theirs := newTestCA(t)
	target := startFakeTarget(t, theirs)

	st, clientKey := registeredAlice(t)
	st.targets["db-1"] = fakeTargetEntry(t, target)

	srv, addr := startServerWith(t, st, ours, t.TempDir())

	res := dial(t, srv, addr, "deploy:db-1", clientKey)

	if res.err == nil {
		t.Fatal("a target trusting a different CA accepted our certificate")
	}
}

func TestExecRunsOnTheTarget(t *testing.T) {
	srv, addr, clientKey, target, _ := withRealTarget(t)

	hostKey, _, _, _, err := ssh.ParseAuthorizedKey(ssh.MarshalAuthorizedKey(srv.hostKey))
	if err != nil {
		t.Fatalf("parse host key: %v", err)
	}

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "deploy:db-1",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientKey)},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer session.Close()

	out, err := session.Output("uptime")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if !strings.Contains(string(out), "welcome to db-1") {
		t.Fatalf("exec output = %q, want the target's output", out)
	}

	waitFor(t, "the target to see the session", func() bool {
		_, _, sessions := target.seen()
		return sessions == 1
	})
}

func TestASessionIsRecordedOpenThenClosed(t *testing.T) {
	ca := newTestCA(t)
	target := startFakeTarget(t, ca)
	st, clientKey := registeredAlice(t)
	st.targets["db-1"] = fakeTargetEntry(t, target)
	srv, addr := startServerWith(t, st, ca, t.TempDir())

	if res := dial(t, srv, addr, "deploy:db-1", clientKey); res.err != nil {
		t.Fatalf("session failed: %v (%s)", res.err, res.stderr)
	}

	opened, closed := st.records()
	if len(opened) != 1 {
		t.Fatalf("%d sessions opened, want 1", len(opened))
	}

	rec := opened[0]
	if !strings.HasPrefix(rec.ID, "ses-") {
		t.Errorf("session id = %q, want a ses- prefix", rec.ID)
	}
	if rec.UserID != aliceID || rec.UserName != "alice" {
		t.Errorf("record = %+v, want alice", rec)
	}
	if rec.TargetName != "db-1" || rec.Principal != "deploy" {
		t.Errorf("record = %+v, want db-1 as deploy", rec)
	}
	if rec.CredentialID != alice.CredentialID {
		t.Errorf("credential = %q, want the key that authenticated", rec.CredentialID)
	}
	if rec.Recording == "" {
		t.Error("the record carries no recording path, so the row indexes nothing")
	}
	if rec.RemoteAddr == "" {
		t.Error("the record carries no remote address")
	}

	end, ok := closed[rec.ID]
	if !ok {
		t.Fatalf("session %s was never closed, so it would stay listed as active forever", rec.ID)
	}
	if end.RecordedBytes == 0 {
		t.Error("the close record reports no recorded bytes")
	}
}

func TestASessionThatCannotBeRecordedInTheStoreIsRefused(t *testing.T) {
	ca := newTestCA(t)
	target := startFakeTarget(t, ca)
	st, clientKey := registeredAlice(t)
	st.targets["db-1"] = fakeTargetEntry(t, target)
	st.openFails = true

	srv, addr := startServerWith(t, st, ca, t.TempDir())

	res := dial(t, srv, addr, "deploy:db-1", clientKey)

	if res.err == nil {
		t.Fatal("a session opened that no operator could list or close")
	}
	if !strings.Contains(res.stderr, "cannot be listed or closed") {
		t.Fatalf("stderr = %q, want it to say why", res.stderr)
	}
	if users, _, _ := target.seen(); len(users) != 0 {
		t.Fatalf("the target authenticated %d times before the session row existed. An unlistable session is also unkillable",
			len(users))
	}
}

func TestARefusedDialStillClosesItsSessionRow(t *testing.T) {
	ca := newTestCA(t)
	target := startFakeTarget(t, ca)
	st, clientKey := registeredAlice(t)
	entry := fakeTargetEntry(t, target)
	entry.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(newKeyPair(t).PublicKey())))
	st.targets["db-1"] = entry

	srv, addr := startServerWith(t, st, ca, t.TempDir())

	if res := dial(t, srv, addr, "deploy:db-1", clientKey); res.err == nil {
		t.Fatal("the dial should have failed on the host key")
	}

	opened, closed := st.records()
	if len(opened) != 1 {
		t.Fatalf("%d sessions opened, want 1", len(opened))
	}
	if _, ok := closed[opened[0].ID]; !ok {
		t.Fatal("a session whose dial failed was left open in the store, so it would list as active and never close")
	}
}

func TestKillClosesALiveSession(t *testing.T) {
	ca := newTestCA(t)
	target := startFakeTarget(t, ca)
	st, clientKey := registeredAlice(t)
	st.targets["db-1"] = fakeTargetEntry(t, target)
	srv, addr := startServerWith(t, st, ca, t.TempDir())

	hostKey, _, _, _, err := ssh.ParseAuthorizedKey(ssh.MarshalAuthorizedKey(srv.hostKey))
	if err != nil {
		t.Fatalf("parse host key: %v", err)
	}

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "deploy:db-1",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientKey)},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	sshSession, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	if _, err := sshSession.StdinPipe(); err != nil {
		t.Fatalf("stdin: %v", err)
	}
	if err := sshSession.Shell(); err != nil {
		t.Fatalf("shell: %v", err)
	}

	waitFor(t, "the session to register as live", func() bool {
		return srv.LiveSessions() == 1
	})

	opened, _ := st.records()
	if len(opened) != 1 {
		t.Fatalf("%d sessions opened, want 1", len(opened))
	}

	if !srv.Kill(opened[0].ID) {
		t.Fatal("Kill reported no live session even though one is registered")
	}

	done := make(chan error, 1)
	go func() { done <- sshSession.Wait() }()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the session did not end after being killed")
	}

	waitFor(t, "the session to deregister", func() bool {
		return srv.LiveSessions() == 0
	})

	_, closed := st.records()
	end, ok := closed[opened[0].ID]
	if !ok {
		t.Fatal("a killed session was not closed in the store")
	}
	if !strings.Contains(end.Reason, "closed by the gateway") {
		t.Fatalf("close reason = %q, want it to say the gateway closed it rather than looking like a normal exit",
			end.Reason)
	}
}

func TestKillingAnUnknownSessionReportsFalse(t *testing.T) {
	st, _ := registeredAlice(t)
	srv, _ := startServer(t, st)

	if srv.Kill("ses-0000000000000") {
		t.Fatal("Kill reported success for a session that was never live")
	}
}

func TestALiveSessionIsDeregisteredWhenItEndsNormally(t *testing.T) {
	ca := newTestCA(t)
	target := startFakeTarget(t, ca)
	st, clientKey := registeredAlice(t)
	st.targets["db-1"] = fakeTargetEntry(t, target)
	srv, addr := startServerWith(t, st, ca, t.TempDir())

	if res := dial(t, srv, addr, "deploy:db-1", clientKey); res.err != nil {
		t.Fatalf("session failed: %v", res.err)
	}

	waitFor(t, "the registry to empty", func() bool {
		return srv.LiveSessions() == 0
	})
}
