package identity

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/marstack-labs/marstack-access/internal/store"
)

type Module struct {
	service *service
	log     *slog.Logger
}

func New(st *store.Store, log *slog.Logger) *Module {
	return &Module{
		service: &service{repo: &repository{db: st.DB()}, now: time.Now},
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
	}
}

func (m *Module) Routes(*http.ServeMux) {}

func (m *Module) Bootstrap(ctx context.Context) (string, error) {
	return m.service.bootstrap(ctx)
}

func (m *Module) Authenticate(ctx context.Context, secret string) (Identity, error) {
	return m.service.authenticate(ctx, secret)
}
