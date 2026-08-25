package authz

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
	"github.com/marstack-labs/marstack-access/internal/kernel/httpx"
)

const (
	RoleViewer   = "viewer"
	RoleOperator = "operator"
	RoleAdmin    = "admin"
)

var ranks = map[string]int{
	RoleViewer:   1,
	RoleOperator: 2,
	RoleAdmin:    3,
}

func Roles() []string {
	return []string{RoleViewer, RoleOperator, RoleAdmin}
}

func Covers(held, required string) bool {
	heldRank, ok := ranks[held]
	if !ok {
		return false
	}
	requiredRank, ok := ranks[required]
	if !ok {
		return false
	}
	return heldRank >= requiredRank
}

type Identity struct {
	UserID  string
	Name    string
	Role    string
	TokenID string
}

type contextKey int

const identityKey contextKey = iota

func IdentityFrom(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityKey).(Identity)
	return id, ok
}

func withIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityKey, id)
}

func InvalidToken() error {
	return fault.Unauthenticated("invalid_token",
		"the token is missing, malformed, expired, or revoked")
}

func InsufficientRole(required string) error {
	return fault.Forbidden("insufficient_role", "this action requires the "+required+" role")
}

type Authenticator interface {
	Authenticate(ctx context.Context, secret string) (Identity, error)
}

type AuthenticatorFunc func(ctx context.Context, secret string) (Identity, error)

func (f AuthenticatorFunc) Authenticate(ctx context.Context, secret string) (Identity, error) {
	return f(ctx, secret)
}

type Guard struct {
	auth Authenticator
	log  *slog.Logger
}

func New(auth Authenticator, log *slog.Logger) *Guard {
	return &Guard{auth: auth, log: log}
}

func Public(next http.Handler) http.Handler {
	return next
}

func (g *Guard) Require(role string, next http.Handler) http.Handler {
	if _, ok := ranks[role]; !ok {
		panic("authz: unknown role " + role)
	}

	return httpx.Wrap(g.log, func(w http.ResponseWriter, r *http.Request) error {
		secret, ok := bearerToken(r)
		if !ok {
			return InvalidToken()
		}

		id, err := g.auth.Authenticate(r.Context(), secret)
		if err != nil {
			return err
		}
		if !Covers(id.Role, role) {
			return InsufficientRole(role)
		}

		next.ServeHTTP(w, r.WithContext(withIdentity(r.Context(), id)))
		return nil
	})
}

func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", false
	}

	scheme, value, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "bearer") {
		return "", false
	}

	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	return value, true
}
