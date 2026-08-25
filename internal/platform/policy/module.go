package policy

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

func New(st *store.Store, log *slog.Logger, guard Guard, targets Targets, trail audit.Trail) *Module {
	if trail == nil {
		trail = audit.Discard()
	}

	return &Module{
		service: &service{
			repo:    &repository{db: st.DB()},
			targets: targets,
			now:     time.Now,
		},
		guard: guard,
		trail: trail,
		log:   log,
	}
}

func (m *Module) Name() string {
	return "policy"
}

func (m *Module) Authorize(ctx context.Context, id authz.Identity, targetID, principal string) error {
	return m.service.Authorize(ctx, id, targetID, principal)
}

func (m *Module) Migrations() []store.Migration {
	return []store.Migration{
		{Module: m.Name(), Index: 1, SQL: `CREATE TABLE policies (
			id           TEXT NOT NULL PRIMARY KEY,
			name         TEXT NOT NULL,
			subject_kind TEXT NOT NULL,
			subject_id   TEXT NOT NULL,
			target_id    TEXT NOT NULL,
			created_at   TEXT NOT NULL
		)`},
		{Module: m.Name(), Index: 2, SQL: `CREATE UNIQUE INDEX policies_name ON policies (name)`},
		{Module: m.Name(), Index: 3, SQL: `CREATE INDEX policies_lookup
			ON policies (target_id, subject_kind, subject_id)`},
		{Module: m.Name(), Index: 4, SQL: `CREATE TABLE policy_principals (
			policy_id TEXT NOT NULL REFERENCES policies (id) ON DELETE CASCADE,
			principal TEXT NOT NULL,
			PRIMARY KEY (policy_id, principal)
		)`},
	}
}

func (m *Module) Routes(mux *http.ServeMux) {
	mux.Handle("POST /v1/policies",
		m.guard.Require(authz.RoleAdmin, httpx.Wrap(m.log, m.handleCreate)))
	mux.Handle("GET /v1/policies",
		m.guard.Require(authz.RoleAdmin, httpx.Wrap(m.log, m.handleList)))
	mux.Handle("GET /v1/policies/{id}",
		m.guard.Require(authz.RoleAdmin, httpx.Wrap(m.log, m.handleGet)))
	mux.Handle("DELETE /v1/policies/{id}",
		m.guard.Require(authz.RoleAdmin, httpx.Wrap(m.log, m.handleDelete)))
	mux.Handle("POST /v1/policies/evaluate",
		m.guard.Require(authz.RoleAdmin, httpx.Wrap(m.log, m.handleEvaluate)))
}

func (m *Module) emit(ctx context.Context, action, object string, fields map[string]string) {
	authz.Emit(ctx, m.trail, m.log, audit.Event{
		Action: action,
		Object: object,
		Fields: fields,
	})
}
