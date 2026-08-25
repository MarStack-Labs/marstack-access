package session

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/marstack-labs/marstack-access/internal/kernel/audit"
	"github.com/marstack-labs/marstack-access/internal/kernel/authz"
	"github.com/marstack-labs/marstack-access/internal/kernel/httpx"
	"github.com/marstack-labs/marstack-access/internal/store"
)

var errUnauthenticatedRoute = errors.New("session: route reached without an identity on the context")

type Guard interface {
	Require(role string, next http.Handler) http.Handler
}

type Module struct {
	service *service
	guard   Guard
	trail   audit.Trail
	log     *slog.Logger
}

func New(st *store.Store, log *slog.Logger, guard Guard, terminator Terminator, trail audit.Trail) *Module {
	if trail == nil {
		trail = audit.Discard()
	}

	return &Module{
		service: &service{
			repo:       &repository{db: st.DB()},
			terminator: terminator,
			log:        log,
			now:        time.Now,
		},
		guard: guard,
		trail: trail,
		log:   log,
	}
}

func (m *Module) Name() string {
	return "session"
}

func (m *Module) Open(ctx context.Context, in OpenInput) error {
	return m.service.open(ctx, in)
}

func (m *Module) Close(ctx context.Context, id string, in CloseInput) error {
	return m.service.close(ctx, id, in)
}

func (m *Module) Reconcile(ctx context.Context) error {
	return m.service.reconcile(ctx)
}

func (m *Module) Migrations() []store.Migration {
	return []store.Migration{
		{Module: m.Name(), Index: 1, SQL: `CREATE TABLE sessions (
			id             TEXT    NOT NULL PRIMARY KEY,
			user_id        TEXT    NOT NULL,
			user_name      TEXT    NOT NULL,
			target_id      TEXT    NOT NULL,
			target_name    TEXT    NOT NULL,
			principal      TEXT    NOT NULL,
			credential_id  TEXT    NOT NULL,
			remote_addr    TEXT    NOT NULL,
			recording      TEXT    NOT NULL,
			started_at     TEXT    NOT NULL,
			ended_at       TEXT,
			exit_code      INTEGER,
			reason         TEXT,
			recorded_bytes INTEGER
		)`},
		{Module: m.Name(), Index: 2, SQL: `CREATE INDEX sessions_open
			ON sessions (ended_at, started_at)`},
		{Module: m.Name(), Index: 3, SQL: `CREATE INDEX sessions_by_user
			ON sessions (user_id, started_at)`},
	}
}

func (m *Module) Routes(mux *http.ServeMux) {
	mux.Handle("GET /v1/sessions",
		m.guard.Require(authz.RoleOperator, httpx.Wrap(m.log, m.handleList)))
	mux.Handle("GET /v1/sessions/{id}",
		m.guard.Require(authz.RoleOperator, httpx.Wrap(m.log, m.handleGet)))
	mux.Handle("POST /v1/sessions/{id}/kill",
		m.guard.Require(authz.RoleAdmin, httpx.Wrap(m.log, m.handleKill)))
}
