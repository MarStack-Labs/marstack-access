package sshd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

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

	srv, err := New(Config{Listen: "127.0.0.1:0", DataDir: t.TempDir()},
		logging.New("error", io.Discard), st, st.lookup, st, st)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

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

func TestAnAuthorizedSessionReportsTheResolvedChain(t *testing.T) {
	st, signer := registeredAlice(t)
	srv, addr := startServer(t, st)

	res := dial(t, srv, addr, "deploy:db-1", signer)
	if res.err != nil {
		t.Fatalf("session failed: %v (stderr: %s)", res.err, res.stderr)
	}

	for _, want := range []string{"authorized", "alice (operator)", "db-1 at 10.0.0.4:22", "deploy"} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("output missing %q:\n%s", want, res.stdout)
		}
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
		logging.New("error", io.Discard), st, st.lookup, st, st)
	if err != nil {
		t.Fatalf("first: %v", err)
	}

	second, err := New(Config{Listen: "127.0.0.1:0", DataDir: dir},
		logging.New("error", io.Discard), st, st.lookup, st, st)
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
		logging.New("error", io.Discard), st, st.lookup, st, st); err != nil {
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
		logging.New("error", io.Discard), st, st.lookup, st, st); err == nil {
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

func TestExecIsTreatedLikeAShell(t *testing.T) {
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

	out, err := session.Output("whoami")
	if err != nil {
		t.Fatalf("exec failed: %v", err)
	}
	if !strings.Contains(string(out), "authorized") {
		t.Fatalf("exec output = %q, want the same verdict a shell gets", out)
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
