package approval

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/marstack-labs/marstack-access/internal/kernel/authz"
	"github.com/marstack-labs/marstack-access/internal/kernel/httpx"
	"github.com/marstack-labs/marstack-access/internal/store"
)

var errUnauthenticatedRoute = errors.New("approval: route reached without an identity on the context")

type Guard interface {
	Require(role string, next http.Handler) http.Handler
}

type Module struct {
	service *service
	guard   Guard
	log     *slog.Logger
}

func New(st *store.Store, log *slog.Logger, guard Guard, policies Policies) *Module {
	return &Module{
		service: &service{
			repo:     &repository{db: st.DB()},
			policies: policies,
			now:      time.Now,
		},
		guard: guard,
		log:   log,
	}
}

func (m *Module) Name() string {
	return "approval"
}

func (m *Module) Migrations() []store.Migration {
	return []store.Migration{
		{Module: m.Name(), Index: 1, SQL: `CREATE TABLE access_requests (
			id                 TEXT    NOT NULL PRIMARY KEY,
			requester_id       TEXT    NOT NULL,
			target_id          TEXT    NOT NULL,
			principal          TEXT    NOT NULL,
			reason             TEXT    NOT NULL,
			state              TEXT    NOT NULL,
			grant_ttl_seconds  INTEGER NOT NULL,
			created_at         TEXT    NOT NULL,
			request_expires_at TEXT    NOT NULL,
			decided_by         TEXT,
			decided_at         TEXT,
			grant_expires_at   TEXT
		)`},
		{Module: m.Name(), Index: 2, SQL: `CREATE INDEX access_requests_grant
			ON access_requests (requester_id, target_id, principal, state, grant_expires_at)`},
		{Module: m.Name(), Index: 3, SQL: `CREATE INDEX access_requests_recent
			ON access_requests (requester_id, created_at)`},
	}
}

func (m *Module) Routes(mux *http.ServeMux) {
	mux.Handle("POST /v1/access-requests",
		m.guard.Require(authz.RoleOperator, httpx.Wrap(m.log, m.handleCreate)))
	mux.Handle("GET /v1/access-requests",
		m.guard.Require(authz.RoleOperator, httpx.Wrap(m.log, m.handleList)))
	mux.Handle("GET /v1/access-requests/{id}",
		m.guard.Require(authz.RoleOperator, httpx.Wrap(m.log, m.handleGet)))
	mux.Handle("POST /v1/access-requests/{id}/cancel",
		m.guard.Require(authz.RoleOperator, httpx.Wrap(m.log, m.handleCancel)))
	mux.Handle("POST /v1/access-requests/{id}/approve",
		m.guard.Require(authz.RoleAdmin, httpx.Wrap(m.log, m.handleApprove)))
	mux.Handle("POST /v1/access-requests/{id}/deny",
		m.guard.Require(authz.RoleAdmin, httpx.Wrap(m.log, m.handleDeny)))
	mux.Handle("POST /v1/access-requests/grant",
		m.guard.Require(authz.RoleAdmin, httpx.Wrap(m.log, m.handleGrant)))
}
