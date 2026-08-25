package authz

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/marstack-labs/marstack-access/internal/kernel/audit"
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
	UserID       string
	Name         string
	Role         string
	CredentialID string
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
	auth  Authenticator
	trail audit.Trail
	log   *slog.Logger
}

func New(auth Authenticator, log *slog.Logger, trail audit.Trail) *Guard {
	if trail == nil {
		trail = Discard()
	}
	return &Guard{auth: auth, trail: trail, log: log}
}

func Emit(ctx context.Context, trail audit.Trail, log *slog.Logger, e audit.Event) {
	if trail == nil {
		return
	}

	if caller, ok := IdentityFrom(ctx); ok {
		if e.ActorID == "" {
			e.ActorID = caller.UserID
		}
		if e.ActorName == "" {
			e.ActorName = caller.Name
		}
	}

	if err := trail.Record(ctx, e); err != nil {
		log.Error("audit event could not be written",
			"action", e.Action, "object", e.Object, "error", err.Error())
	}
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
			g.deny(r, "", "", "missing_token", role)
			return InvalidToken()
		}

		id, err := g.auth.Authenticate(r.Context(), secret)
		if err != nil {
			g.deny(r, "", "", fault.From(err).Code, role)
			return err
		}
		if !Covers(id.Role, role) {
			g.deny(r, id.UserID, id.Name, "insufficient_role", role)
			return InsufficientRole(role)
		}

		next.ServeHTTP(w, r.WithContext(withIdentity(r.Context(), id)))
		return nil
	})
}

func (g *Guard) deny(r *http.Request, actorID, actorName, reason, required string) {
	Emit(r.Context(), g.trail, g.log, audit.Event{
		Action:    "api.denied",
		Outcome:   audit.OutcomeDenied,
		ActorID:   actorID,
		ActorName: actorName,
		Reason:    reason,
		Fields: map[string]string{
			"method":   r.Method,
			"path":     r.URL.Path,
			"required": required,
			"remote":   r.RemoteAddr,
		},
	})
}

func Discard() audit.Trail {
	return audit.Discard()
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
