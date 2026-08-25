package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/marstack-labs/marstack-access/internal/kernel/audit"
	"github.com/marstack-labs/marstack-access/internal/kernel/authz"
	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
	"github.com/marstack-labs/marstack-access/internal/kernel/logging"
	"github.com/marstack-labs/marstack-access/internal/kernel/sshkey"
	"github.com/marstack-labs/marstack-access/internal/store"
)

type passThroughGuard struct{}

func (passThroughGuard) Require(_ string, next http.Handler) http.Handler {
	return next
}

type clock struct {
	at time.Time
}

func (c *clock) now() time.Time {
	return c.at
}

func newTestModule(t *testing.T) (*Module, *clock) {
	t.Helper()

	trail := &recordingTrail{}
	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	m := New(st, logging.New("error", io.Discard), passThroughGuard{}, trail)
	if err := st.Migrate(context.Background(), m.Migrations()); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	c := &clock{at: time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)}
	m.service.now = c.now
	return m, c
}

func mustCreateUser(t *testing.T, m *Module, name, role string) User {
	t.Helper()

	u, err := m.service.createUser(context.Background(), CreateUserInput{Name: name, Role: role})
	if err != nil {
		t.Fatalf("create user %q: %v", name, err)
	}
	return u
}

func mustIssueToken(t *testing.T, m *Module, userID string, ttl time.Duration) (Token, string) {
	t.Helper()

	tok, secret, err := m.service.issueToken(context.Background(), userID, ttl)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	return tok, secret
}

func faultOf(t *testing.T, err error) *fault.Fault {
	t.Helper()

	if err == nil {
		t.Fatal("expected an error")
	}
	return fault.From(err)
}

func TestCreateUserValidatesNameAndRole(t *testing.T) {
	m, _ := newTestModule(t)
	ctx := context.Background()

	cases := map[string]CreateUserInput{
		"empty name":   {Name: "", Role: authz.RoleAdmin},
		"bad name":     {Name: "Umar Sabirin", Role: authz.RoleAdmin},
		"empty role":   {Name: "umar", Role: ""},
		"unknown role": {Name: "umar", Role: "superadmin"},
		"role casing":  {Name: "umar", Role: "Admin"},
	}

	for label, in := range cases {
		if _, err := m.service.createUser(ctx, in); err == nil {
			t.Errorf("%s: expected an error", label)
		} else if faultOf(t, err).Kind != fault.KindInvalid {
			t.Errorf("%s: kind = %v, want KindInvalid", label, faultOf(t, err).Kind)
		}
	}
}

func TestCreateUserRejectsADuplicateName(t *testing.T) {
	m, _ := newTestModule(t)
	mustCreateUser(t, m, "umar", authz.RoleAdmin)

	_, err := m.service.createUser(context.Background(), CreateUserInput{Name: "umar", Role: authz.RoleViewer})
	if got := faultOf(t, err); got.Kind != fault.KindConflict || got.Code != "user_name_taken" {
		t.Fatalf("fault = %+v, want a user_name_taken conflict", got)
	}
}

func TestAuthenticateAcceptsAFreshToken(t *testing.T) {
	m, _ := newTestModule(t)
	u := mustCreateUser(t, m, "umar", authz.RoleOperator)
	tok, secret := mustIssueToken(t, m, u.ID, 0)

	id, err := m.Authenticate(context.Background(), secret)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	if id.UserID != u.ID || id.Name != "umar" || id.Role != authz.RoleOperator || id.CredentialID != tok.ID {
		t.Fatalf("identity = %+v, want it to name the user and the token used", id)
	}
}

func TestEveryAuthenticationFailureLooksTheSame(t *testing.T) {
	ctx := context.Background()

	build := func(t *testing.T) (*Module, *clock, string) {
		t.Helper()
		m, c := newTestModule(t)
		u := mustCreateUser(t, m, "umar", authz.RoleOperator)
		_, secret := mustIssueToken(t, m, u.ID, time.Hour)
		return m, c, secret
	}

	cases := map[string]func(t *testing.T) (*Module, string){
		"malformed": func(t *testing.T) (*Module, string) {
			m, _, _ := build(t)
			return m, "not-a-token"
		},
		"unknown selector": func(t *testing.T) (*Module, string) {
			m, _, _ := build(t)
			other, _ := newSecret()
			return m, other
		},
		"wrong verifier": func(t *testing.T) (*Module, string) {
			m, _, secret := build(t)
			parts, _ := parseSecret(secret)
			return m, tokenPrefix + "_" + parts.selector + "_" + strings.Repeat("0", len(parts.verifier))
		},
		"expired": func(t *testing.T) (*Module, string) {
			m, c, secret := build(t)
			c.at = c.at.Add(2 * time.Hour)
			return m, secret
		},
		"revoked": func(t *testing.T) (*Module, string) {
			m, _, secret := build(t)
			parts, _ := parseSecret(secret)
			rec, err := m.service.repo.tokenBySelector(ctx, parts.selector)
			if err != nil {
				t.Fatalf("lookup token: %v", err)
			}
			if err := m.service.revokeToken(ctx, rec.ID); err != nil {
				t.Fatalf("revoke: %v", err)
			}
			return m, secret
		},
		"user deleted": func(t *testing.T) (*Module, string) {
			m, _, secret := build(t)
			users, err := m.service.listUsers(ctx)
			if err != nil {
				t.Fatalf("list users: %v", err)
			}
			if err := m.service.deleteUser(ctx, users[0].ID); err != nil {
				t.Fatalf("delete user: %v", err)
			}
			return m, secret
		},
		"empty": func(t *testing.T) (*Module, string) {
			m, _, _ := build(t)
			return m, ""
		},
	}

	want := faultOf(t, authz.InvalidToken())

	for label, setup := range cases {
		m, secret := setup(t)

		_, err := m.Authenticate(ctx, secret)
		got := faultOf(t, err)

		if got.Kind != want.Kind || got.Code != want.Code || got.Message != want.Message {
			t.Errorf("%s: fault = {%v %s %q}, want {%v %s %q}: a distinguishable failure tells an attacker which half of the token was right",
				label, got.Kind, got.Code, got.Message, want.Kind, want.Code, want.Message)
		}
	}
}

func TestAnExpiredTokenIsRejectedExactlyAtExpiry(t *testing.T) {
	m, c := newTestModule(t)
	u := mustCreateUser(t, m, "umar", authz.RoleOperator)
	_, secret := mustIssueToken(t, m, u.ID, time.Hour)
	ctx := context.Background()

	c.at = c.at.Add(time.Hour - time.Second)
	if _, err := m.Authenticate(ctx, secret); err != nil {
		t.Fatalf("rejected one second before expiry: %v", err)
	}

	c.at = c.at.Add(time.Second)
	if _, err := m.Authenticate(ctx, secret); err == nil {
		t.Fatal("accepted at the expiry instant: the window must be half-open")
	}
}

func TestATokenWithNoTTLDoesNotExpire(t *testing.T) {
	m, c := newTestModule(t)
	u := mustCreateUser(t, m, "umar", authz.RoleAdmin)
	_, secret := mustIssueToken(t, m, u.ID, 0)

	c.at = c.at.Add(100 * 365 * 24 * time.Hour)

	if _, err := m.Authenticate(context.Background(), secret); err != nil {
		t.Fatalf("a token issued without a ttl expired: %v", err)
	}
}

func TestIssueTokenRejectsAnAbsurdTTL(t *testing.T) {
	m, _ := newTestModule(t)
	u := mustCreateUser(t, m, "umar", authz.RoleAdmin)

	for _, ttl := range []time.Duration{-time.Second, maxTokenTTL + time.Second} {
		if _, _, err := m.service.issueToken(context.Background(), u.ID, ttl); err == nil {
			t.Errorf("ttl %s was accepted", ttl)
		}
	}
}

func TestIssueTokenRejectsAnUnknownUser(t *testing.T) {
	m, _ := newTestModule(t)

	_, _, err := m.service.issueToken(context.Background(), "usr-0000000000000", 0)
	if got := faultOf(t, err); got.Kind != fault.KindNotFound {
		t.Fatalf("kind = %v, want KindNotFound", got.Kind)
	}
}

func TestDeletingAUserRevokesItsTokens(t *testing.T) {
	m, _ := newTestModule(t)
	ctx := context.Background()
	u := mustCreateUser(t, m, "umar", authz.RoleAdmin)
	mustIssueToken(t, m, u.ID, 0)
	mustIssueToken(t, m, u.ID, 0)

	if err := m.service.deleteUser(ctx, u.ID); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	var count int
	if err := m.service.repo.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM tokens`).Scan(&count); err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	if count != 0 {
		t.Fatalf("%d tokens survived the user: a deleted account must not keep working", count)
	}
}

func TestListTokensNeverExposesTheVerifier(t *testing.T) {
	m, _ := newTestModule(t)
	u := mustCreateUser(t, m, "umar", authz.RoleAdmin)
	_, secret := mustIssueToken(t, m, u.ID, 0)
	parts, _ := parseSecret(secret)

	tokens, err := m.service.listTokens(context.Background(), u.ID)
	if err != nil {
		t.Fatalf("list tokens: %v", err)
	}
	if len(tokens) != 1 {
		t.Fatalf("got %d tokens, want 1", len(tokens))
	}

	if strings.Contains(tokens[0].Selector, parts.verifier) {
		t.Fatal("the selector carries the verifier")
	}
	if tokens[0].Selector != parts.selector {
		t.Fatalf("selector = %q, want the issued selector so a token can be named without being usable",
			tokens[0].Selector)
	}
}

func TestBootstrapCreatesAnAdminOnlyOnce(t *testing.T) {
	m, _ := newTestModule(t)
	ctx := context.Background()

	secret, err := m.Bootstrap(ctx)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if secret == "" {
		t.Fatal("bootstrap on an empty store returned no secret")
	}

	id, err := m.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("the bootstrap secret does not authenticate: %v", err)
	}
	if id.Role != authz.RoleAdmin || id.Name != bootstrapUserName {
		t.Fatalf("identity = %+v, want the %s admin", id, bootstrapUserName)
	}

	again, err := m.Bootstrap(ctx)
	if err != nil {
		t.Fatalf("second bootstrap: %v", err)
	}
	if again != "" {
		t.Fatal("bootstrap issued a second credential on a populated store, so every restart would mint an admin token")
	}
}

func TestBootstrapDoesNotRunWhenAnyUserExists(t *testing.T) {
	m, _ := newTestModule(t)
	mustCreateUser(t, m, "umar", authz.RoleViewer)

	secret, err := m.Bootstrap(context.Background())
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if secret != "" {
		t.Fatal("bootstrap ran despite an existing user: a viewer-only install would silently gain an admin")
	}
}

func TestTwoTokensForTheSameUserBothWork(t *testing.T) {
	m, _ := newTestModule(t)
	ctx := context.Background()
	u := mustCreateUser(t, m, "umar", authz.RoleOperator)

	_, first := mustIssueToken(t, m, u.ID, 0)
	_, second := mustIssueToken(t, m, u.ID, 0)

	if first == second {
		t.Fatal("two issued secrets are identical")
	}
	for _, secret := range []string{first, second} {
		if _, err := m.Authenticate(ctx, secret); err != nil {
			t.Errorf("token rejected: %v", err)
		}
	}
}

func TestRevokingOneTokenLeavesTheOther(t *testing.T) {
	m, _ := newTestModule(t)
	ctx := context.Background()
	u := mustCreateUser(t, m, "umar", authz.RoleOperator)

	firstToken, first := mustIssueToken(t, m, u.ID, 0)
	_, second := mustIssueToken(t, m, u.ID, 0)

	if err := m.service.revokeToken(ctx, firstToken.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if _, err := m.Authenticate(ctx, first); err == nil {
		t.Error("the revoked token still authenticates")
	}
	if _, err := m.Authenticate(ctx, second); err != nil {
		t.Errorf("the other token stopped working: %v", err)
	}
}

func TestRevokeRejectsAMalformedID(t *testing.T) {
	m, _ := newTestModule(t)

	if err := m.service.revokeToken(context.Background(), "usr-abc"); err == nil {
		t.Fatal("a user id was accepted as a token id")
	}
}

func TestIdentityCarriesNoSecretMaterial(t *testing.T) {
	m, _ := newTestModule(t)
	u := mustCreateUser(t, m, "umar", authz.RoleAdmin)
	_, secret := mustIssueToken(t, m, u.ID, 0)

	id, err := m.Authenticate(context.Background(), secret)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	rendered := id.UserID + id.Name + id.Role + id.CredentialID
	if strings.Contains(rendered, secret) {
		t.Fatal("the identity carries the secret, so anything that logs an identity logs a credential")
	}
	parts, _ := parseSecret(secret)
	if strings.Contains(rendered, parts.verifier) {
		t.Fatal("the identity carries the verifier")
	}
}

func generateKey(t *testing.T) string {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
}

func mustAddKey(t *testing.T, m *Module, userID, name, raw string) Key {
	t.Helper()

	k, err := m.service.addKey(context.Background(), userID, AddKeyInput{Name: name, PublicKey: raw})
	if err != nil {
		t.Fatalf("add key: %v", err)
	}
	return k
}

func TestAKeyResolvesToItsOwner(t *testing.T) {
	m, _ := newTestModule(t)
	u := mustCreateUser(t, m, "alice", authz.RoleOperator)
	raw := generateKey(t)
	k := mustAddKey(t, m, u.ID, "laptop", raw)

	id, err := m.ByPublicKey(context.Background(), k.Fingerprint)
	if err != nil {
		t.Fatalf("by public key: %v", err)
	}
	if id.UserID != u.ID || id.Role != authz.RoleOperator {
		t.Fatalf("identity = %+v, want alice the operator", id)
	}
	if id.CredentialID != k.ID {
		t.Fatalf("credential = %q, want the key id %q so an audit line names what was used",
			id.CredentialID, k.ID)
	}
}

func TestOneKeyCannotBelongToTwoUsers(t *testing.T) {
	m, _ := newTestModule(t)
	alice := mustCreateUser(t, m, "alice", authz.RoleOperator)
	bob := mustCreateUser(t, m, "bob", authz.RoleAdmin)
	raw := generateKey(t)

	mustAddKey(t, m, alice.ID, "laptop", raw)

	_, err := m.service.addKey(context.Background(), bob.ID, AddKeyInput{Name: "laptop", PublicKey: raw})
	got := faultOf(t, err)
	if got.Kind != fault.KindConflict || got.Code != "public_key_registered" {
		t.Fatalf("fault = %+v, want a public_key_registered conflict. If one key resolved to two users, the platform could not say who acted",
			got)
	}
}

func TestAUserMayHoldSeveralKeys(t *testing.T) {
	m, _ := newTestModule(t)
	u := mustCreateUser(t, m, "alice", authz.RoleOperator)
	ctx := context.Background()

	first := mustAddKey(t, m, u.ID, "laptop", generateKey(t))
	second := mustAddKey(t, m, u.ID, "yubikey", generateKey(t))

	for _, k := range []Key{first, second} {
		if _, err := m.ByPublicKey(ctx, k.Fingerprint); err != nil {
			t.Errorf("key %q does not authenticate: %v", k.Name, err)
		}
	}

	if _, err := m.service.addKey(ctx, u.ID, AddKeyInput{Name: "laptop", PublicKey: generateKey(t)}); err == nil {
		t.Error("a second key reused the name laptop for the same user")
	}
}

func TestAWeakOrUnsupportedKeyIsRefused(t *testing.T) {
	m, _ := newTestModule(t)
	u := mustCreateUser(t, m, "alice", authz.RoleOperator)
	ctx := context.Background()

	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}
	weakSigner, err := ssh.NewSignerFromKey(weak)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	cases := map[string]string{
		"not a key":     "hello world",
		"empty":         "",
		"private key":   "-----BEGIN OPENSSH PRIVATE KEY-----\nnope\n-----END OPENSSH PRIVATE KEY-----",
		"rsa 1024 bits": string(ssh.MarshalAuthorizedKey(weakSigner.PublicKey())),
	}

	for label, raw := range cases {
		_, err := m.service.addKey(ctx, u.ID, AddKeyInput{Name: "k", PublicKey: raw})
		if got := faultOf(t, err); got.Kind != fault.KindInvalid {
			t.Errorf("%s: kind = %v, want KindInvalid", label, got.Kind)
		}
	}
}

func TestAStrongRSAKeyIsAccepted(t *testing.T) {
	m, _ := newTestModule(t)
	u := mustCreateUser(t, m, "alice", authz.RoleOperator)

	strong, err := rsa.GenerateKey(rand.Reader, sshkey.MinRSABits)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(strong)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	mustAddKey(t, m, u.ID, "old-laptop", string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}

func TestAnUnknownFingerprintIsRefusedUniformly(t *testing.T) {
	m, _ := newTestModule(t)
	u := mustCreateUser(t, m, "alice", authz.RoleOperator)
	k := mustAddKey(t, m, u.ID, "laptop", generateKey(t))
	ctx := context.Background()

	want := faultOf(t, unknownKey())

	for label, fingerprint := range map[string]string{
		"empty":        "",
		"garbage":      "SHA256:not-a-real-fingerprint",
		"almost":       k.Fingerprint + "x",
		"unregistered": "SHA256:" + strings.Repeat("A", 43),
	} {
		_, err := m.ByPublicKey(ctx, fingerprint)
		got := faultOf(t, err)
		if got.Code != want.Code || got.Message != want.Message {
			t.Errorf("%s: fault = {%s %q}, want {%s %q}", label, got.Code, got.Message, want.Code, want.Message)
		}
	}
}

func TestRemovingAKeyStopsItAuthenticating(t *testing.T) {
	m, _ := newTestModule(t)
	u := mustCreateUser(t, m, "alice", authz.RoleOperator)
	ctx := context.Background()
	k := mustAddKey(t, m, u.ID, "laptop", generateKey(t))

	if err := m.service.removeKey(ctx, k.ID); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := m.ByPublicKey(ctx, k.Fingerprint); err == nil {
		t.Fatal("a removed key still authenticates")
	}
	if err := m.service.removeKey(ctx, k.ID); err == nil {
		t.Error("a second removal reported success it did not perform")
	}
}

func TestDeletingAUserRemovesItsKeys(t *testing.T) {
	m, _ := newTestModule(t)
	u := mustCreateUser(t, m, "alice", authz.RoleOperator)
	ctx := context.Background()
	k := mustAddKey(t, m, u.ID, "laptop", generateKey(t))

	if err := m.service.deleteUser(ctx, u.ID); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	if _, err := m.ByPublicKey(ctx, k.Fingerprint); err == nil {
		t.Fatal("a deleted user's key still authenticates")
	}
}

func TestTheKeyViewNeverCarriesTheKeyMaterial(t *testing.T) {
	m, _ := newTestModule(t)
	u := mustCreateUser(t, m, "alice", authz.RoleOperator)
	raw := generateKey(t)
	k := mustAddKey(t, m, u.ID, "laptop", raw)

	encoded, err := json.Marshal(keyViewOf(k))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(encoded), "ssh-ed25519 ") {
		t.Fatalf("the view carries the authorized_keys line: %s", encoded)
	}
	if !strings.Contains(string(encoded), k.Fingerprint) {
		t.Fatalf("the view has no fingerprint, so an operator cannot match it to a client: %s", encoded)
	}
}

func TestAFreshKeyGrantsNoAccessByItself(t *testing.T) {
	m, _ := newTestModule(t)
	u := mustCreateUser(t, m, "alice", authz.RoleViewer)
	k := mustAddKey(t, m, u.ID, "laptop", generateKey(t))

	id, err := m.ByPublicKey(context.Background(), k.Fingerprint)
	if err != nil {
		t.Fatalf("by public key: %v", err)
	}
	if id.Role != authz.RoleViewer {
		t.Fatalf("role = %q, want the user's own role: registering a key must not change what the account may do", id.Role)
	}
}

type recordingTrail struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recordingTrail) Record(_ context.Context, e audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events = append(r.events, e)
	return nil
}

func (r *recordingTrail) find(action string) (audit.Event, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, e := range r.events {
		if e.Action == action {
			return e, true
		}
	}
	return audit.Event{}, false
}

func newTestModuleWithTrail(t *testing.T) (*Module, *recordingTrail) {
	t.Helper()

	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	trail := &recordingTrail{}
	m := New(st, logging.New("error", io.Discard), passThroughGuard{}, trail)
	if err := st.Migrate(context.Background(), m.Migrations()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return m, trail
}

func TestIdentityChangesLandInTheTrail(t *testing.T) {
	m, trail := newTestModuleWithTrail(t)
	ctx := context.Background()

	u, err := m.service.createUser(ctx, CreateUserInput{Name: "alice", Role: authz.RoleOperator})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	mux := http.NewServeMux()
	m.Routes(mux)

	send := func(method, path, body string) *httptest.ResponseRecorder {
		var reader io.Reader
		if body != "" {
			reader = strings.NewReader(body)
		}
		r := httptest.NewRequest(method, path, reader)
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		return rec
	}

	issued := send(http.MethodPost, "/v1/users/"+u.ID+"/tokens", "")
	if issued.Code != http.StatusCreated {
		t.Fatalf("issue token: %d (%s)", issued.Code, issued.Body)
	}

	var view issuedTokenView
	if err := json.Unmarshal(issued.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}

	event, ok := trail.find("token.issued")
	if !ok {
		t.Fatal("issuing a token left no audit event")
	}
	if event.Object != view.ID {
		t.Errorf("object = %q, want the token id %q", event.Object, view.ID)
	}

	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	if strings.Contains(string(encoded), view.Secret) {
		t.Fatalf("the audit event carries the token secret. The trail is written to disk and shipped off host, so a secret in it is a secret in two more places: %s",
			encoded)
	}
	if !strings.Contains(string(encoded), view.Selector) {
		t.Error("the event carries no selector, so the trail cannot name which token was issued")
	}
}

func TestAddingAKeyRecordsItsFingerprint(t *testing.T) {
	m, trail := newTestModuleWithTrail(t)
	ctx := context.Background()

	u, err := m.service.createUser(ctx, CreateUserInput{Name: "alice", Role: authz.RoleOperator})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	mux := http.NewServeMux()
	m.Routes(mux)

	raw := strings.TrimSpace(generateKey(t))
	body := `{"name":"laptop","public_key":"` + raw + `"}`
	r := httptest.NewRequest(http.MethodPost, "/v1/users/"+u.ID+"/keys", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)

	if rec.Code != http.StatusCreated {
		t.Fatalf("add key: %d (%s)", rec.Code, rec.Body)
	}

	event, ok := trail.find("key.added")
	if !ok {
		t.Fatal("adding a key left no audit event")
	}
	parsed, err := sshkey.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if event.Fields["fingerprint"] != parsed.Fingerprint {
		t.Fatalf("fingerprint = %q, want %q: without it the trail cannot say which key was trusted",
			event.Fields["fingerprint"], parsed.Fingerprint)
	}
}
