package identity

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/marstack-labs/marstack-access/internal/kernel/audit"
	"github.com/marstack-labs/marstack-access/internal/kernel/authz"
	"github.com/marstack-labs/marstack-access/internal/kernel/httpx"
	"github.com/marstack-labs/marstack-access/internal/store"
)

type Guard interface {
	Require(role string, next http.Handler) http.Handler
}

type Module struct {
	service *service
	guard   Guard
	trail   audit.Trail
	log     *slog.Logger
}

func New(st *store.Store, log *slog.Logger, guard Guard, trail audit.Trail) *Module {
	if trail == nil {
		trail = audit.Discard()
	}

	return &Module{
		service: &service{repo: &repository{db: st.DB()}, now: time.Now},
		guard:   guard,
		trail:   trail,
		log:     log,
	}
}

func (m *Module) Name() string {
	return "identity"
}

func (m *Module) Migrations() []store.Migration {
	return []store.Migration{
		{Module: m.Name(), Index: 1, SQL: `CREATE TABLE users (
			id         TEXT    NOT NULL PRIMARY KEY,
			name       TEXT    NOT NULL,
			role       TEXT    NOT NULL,
			disabled   INTEGER NOT NULL DEFAULT 0,
			created_at TEXT    NOT NULL
		)`},
		{Module: m.Name(), Index: 2, SQL: `CREATE UNIQUE INDEX users_name ON users (name)`},
		{Module: m.Name(), Index: 3, SQL: `CREATE TABLE tokens (
			id            TEXT NOT NULL PRIMARY KEY,
			user_id       TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
			selector      TEXT NOT NULL,
			verifier_hash BLOB NOT NULL,
			created_at    TEXT NOT NULL,
			expires_at    TEXT
		)`},
		{Module: m.Name(), Index: 4, SQL: `CREATE UNIQUE INDEX tokens_selector ON tokens (selector)`},
		{Module: m.Name(), Index: 5, SQL: `CREATE TABLE user_keys (
			id             TEXT NOT NULL PRIMARY KEY,
			user_id        TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
			name           TEXT NOT NULL,
			key_type       TEXT NOT NULL,
			fingerprint    TEXT NOT NULL,
			authorized_key TEXT NOT NULL,
			created_at     TEXT NOT NULL
		)`},
		{Module: m.Name(), Index: 6, SQL: `CREATE UNIQUE INDEX user_keys_fingerprint
			ON user_keys (fingerprint)`},
		{Module: m.Name(), Index: 7, SQL: `CREATE UNIQUE INDEX user_keys_name
			ON user_keys (user_id, name)`},
	}
}

func (m *Module) Routes(mux *http.ServeMux) {
	mux.Handle("POST /v1/users",
		m.guard.Require(authz.RoleAdmin, httpx.Wrap(m.log, m.handleCreateUser)))
	mux.Handle("GET /v1/users",
		m.guard.Require(authz.RoleAdmin, httpx.Wrap(m.log, m.handleListUsers)))
	mux.Handle("GET /v1/users/{id}",
		m.guard.Require(authz.RoleAdmin, httpx.Wrap(m.log, m.handleGetUser)))
	mux.Handle("DELETE /v1/users/{id}",
		m.guard.Require(authz.RoleAdmin, httpx.Wrap(m.log, m.handleDeleteUser)))
	mux.Handle("POST /v1/users/{id}/tokens",
		m.guard.Require(authz.RoleAdmin, httpx.Wrap(m.log, m.handleIssueToken)))
	mux.Handle("GET /v1/users/{id}/tokens",
		m.guard.Require(authz.RoleAdmin, httpx.Wrap(m.log, m.handleListTokens)))
	mux.Handle("DELETE /v1/tokens/{id}",
		m.guard.Require(authz.RoleAdmin, httpx.Wrap(m.log, m.handleRevokeToken)))
	mux.Handle("POST /v1/users/{id}/keys",
		m.guard.Require(authz.RoleAdmin, httpx.Wrap(m.log, m.handleAddKey)))
	mux.Handle("GET /v1/users/{id}/keys",
		m.guard.Require(authz.RoleAdmin, httpx.Wrap(m.log, m.handleListKeys)))
	mux.Handle("DELETE /v1/keys/{id}",
		m.guard.Require(authz.RoleAdmin, httpx.Wrap(m.log, m.handleRemoveKey)))
}

func (m *Module) ByPublicKey(ctx context.Context, fingerprint string) (authz.Identity, error) {
	return m.service.byPublicKey(ctx, fingerprint)
}

func (m *Module) Bootstrap(ctx context.Context) (string, error) {
	return m.service.bootstrap(ctx)
}

func (m *Module) Authenticate(ctx context.Context, secret string) (authz.Identity, error) {
	return m.service.authenticate(ctx, secret)
}

func (m *Module) emit(ctx context.Context, action, object string, fields map[string]string) {
	authz.Emit(ctx, m.trail, m.log, audit.Event{
		Action: action,
		Object: object,
		Fields: fields,
	})
}
