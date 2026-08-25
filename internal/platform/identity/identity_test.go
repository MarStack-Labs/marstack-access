package identity

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
	"github.com/marstack-labs/marstack-access/internal/kernel/logging"
	"github.com/marstack-labs/marstack-access/internal/store"
)

type clock struct {
	at time.Time
}

func (c *clock) now() time.Time {
	return c.at
}

func newTestModule(t *testing.T) (*Module, *clock) {
	t.Helper()

	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	m := New(st, logging.New("error", io.Discard))
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
		"empty name":   {Name: "", Role: RoleAdmin},
		"bad name":     {Name: "Umar Sabirin", Role: RoleAdmin},
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
	mustCreateUser(t, m, "umar", RoleAdmin)

	_, err := m.service.createUser(context.Background(), CreateUserInput{Name: "umar", Role: RoleViewer})
	if got := faultOf(t, err); got.Kind != fault.KindConflict || got.Code != "user_name_taken" {
		t.Fatalf("fault = %+v, want a user_name_taken conflict", got)
	}
}

func TestAuthenticateAcceptsAFreshToken(t *testing.T) {
	m, _ := newTestModule(t)
	u := mustCreateUser(t, m, "umar", RoleOperator)
	tok, secret := mustIssueToken(t, m, u.ID, 0)

	id, err := m.Authenticate(context.Background(), secret)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	if id.UserID != u.ID || id.Name != "umar" || id.Role != RoleOperator || id.TokenID != tok.ID {
		t.Fatalf("identity = %+v, want it to name the user and the token used", id)
	}
}

func TestEveryAuthenticationFailureLooksTheSame(t *testing.T) {
	ctx := context.Background()

	build := func(t *testing.T) (*Module, *clock, string) {
		t.Helper()
		m, c := newTestModule(t)
		u := mustCreateUser(t, m, "umar", RoleOperator)
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

	want := faultOf(t, invalidToken())

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
	u := mustCreateUser(t, m, "umar", RoleOperator)
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
	u := mustCreateUser(t, m, "umar", RoleAdmin)
	_, secret := mustIssueToken(t, m, u.ID, 0)

	c.at = c.at.Add(100 * 365 * 24 * time.Hour)

	if _, err := m.Authenticate(context.Background(), secret); err != nil {
		t.Fatalf("a token issued without a ttl expired: %v", err)
	}
}

func TestIssueTokenRejectsAnAbsurdTTL(t *testing.T) {
	m, _ := newTestModule(t)
	u := mustCreateUser(t, m, "umar", RoleAdmin)

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
	u := mustCreateUser(t, m, "umar", RoleAdmin)
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
	u := mustCreateUser(t, m, "umar", RoleAdmin)
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
	if id.Role != RoleAdmin || id.Name != bootstrapUserName {
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
	mustCreateUser(t, m, "umar", RoleViewer)

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
	u := mustCreateUser(t, m, "umar", RoleOperator)

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
	u := mustCreateUser(t, m, "umar", RoleOperator)

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
	u := mustCreateUser(t, m, "umar", RoleAdmin)
	_, secret := mustIssueToken(t, m, u.ID, 0)

	id, err := m.Authenticate(context.Background(), secret)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	rendered := id.UserID + id.Name + id.Role + id.TokenID
	if strings.Contains(rendered, secret) {
		t.Fatal("the identity carries the secret, so anything that logs an identity logs a credential")
	}
	parts, _ := parseSecret(secret)
	if strings.Contains(rendered, parts.verifier) {
		t.Fatal("the identity carries the verifier")
	}
}
