package target

import (
	"context"
	"log/slog"
	"net/http"
	"time"

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
	log     *slog.Logger
}

func New(st *store.Store, log *slog.Logger, guard Guard) *Module {
	return &Module{
		service: &service{repo: &repository{db: st.DB()}, now: time.Now},
		guard:   guard,
		log:     log,
	}
}

func (m *Module) Name() string {
	return "target"
}

func (m *Module) ByName(ctx context.Context, name string) (Target, error) {
	return m.service.getByName(ctx, name)
}

func (m *Module) Principals(ctx context.Context, targetID string) ([]string, error) {
	t, err := m.service.get(ctx, targetID)
	if err != nil {
		return nil, err
	}
	return t.Principals, nil
}

func (m *Module) Migrations() []store.Migration {
	return []store.Migration{
		{Module: m.Name(), Index: 1, SQL: `CREATE TABLE targets (
			id         TEXT    NOT NULL PRIMARY KEY,
			name       TEXT    NOT NULL,
			address    TEXT    NOT NULL,
			port       INTEGER NOT NULL,
			created_at TEXT    NOT NULL
		)`},
		{Module: m.Name(), Index: 2, SQL: `CREATE UNIQUE INDEX targets_name ON targets (name)`},
		{Module: m.Name(), Index: 3, SQL: `CREATE TABLE target_principals (
			target_id TEXT NOT NULL REFERENCES targets (id) ON DELETE CASCADE,
			principal TEXT NOT NULL,
			PRIMARY KEY (target_id, principal)
		)`},
	}
}

func (m *Module) Routes(mux *http.ServeMux) {
	mux.Handle("POST /v1/targets",
		m.guard.Require(authz.RoleOperator, httpx.Wrap(m.log, m.handleRegister)))
	mux.Handle("GET /v1/targets",
		m.guard.Require(authz.RoleOperator, httpx.Wrap(m.log, m.handleList)))
	mux.Handle("GET /v1/targets/{id}",
		m.guard.Require(authz.RoleOperator, httpx.Wrap(m.log, m.handleGet)))
	mux.Handle("DELETE /v1/targets/{id}",
		m.guard.Require(authz.RoleOperator, httpx.Wrap(m.log, m.handleDelete)))
}
