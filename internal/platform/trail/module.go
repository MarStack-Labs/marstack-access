package trail

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/marstack-labs/marstack-access/internal/kernel/audit"
	"github.com/marstack-labs/marstack-access/internal/kernel/authz"
	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
	"github.com/marstack-labs/marstack-access/internal/kernel/httpx"
	"github.com/marstack-labs/marstack-access/internal/store"
)

const defaultLimit = 100

type Guard interface {
	Require(role string, next http.Handler) http.Handler
}

type Reader func(limit int) ([]audit.Event, error)

type Module struct {
	read    Reader
	shipped bool
	guard   Guard
	log     *slog.Logger
}

func New(read Reader, shipped bool, log *slog.Logger, guard Guard) *Module {
	return &Module{read: read, shipped: shipped, guard: guard, log: log}
}

func (m *Module) Name() string {
	return "trail"
}

func (m *Module) Migrations() []store.Migration {
	return nil
}

func (m *Module) Routes(mux *http.ServeMux) {
	mux.Handle("GET /v1/audit",
		m.guard.Require(authz.RoleAdmin, httpx.Wrap(m.log, m.handleTail)))
}

type eventView struct {
	At        string            `json:"at"`
	Action    string            `json:"action"`
	Outcome   string            `json:"outcome"`
	ActorID   string            `json:"actor_id,omitempty"`
	ActorName string            `json:"actor_name,omitempty"`
	Object    string            `json:"object,omitempty"`
	Reason    string            `json:"reason,omitempty"`
	Fields    map[string]string `json:"fields,omitempty"`
}

type tailView struct {
	Events  []eventView `json:"events"`
	Limit   int         `json:"limit"`
	Max     int         `json:"max"`
	Shipped bool        `json:"shipped"`
}

func (m *Module) handleTail(w http.ResponseWriter, r *http.Request) error {
	limit, err := limitOf(r)
	if err != nil {
		return err
	}

	events, err := m.read(limit)
	if err != nil {
		m.log.Error("the audit trail could not be read", "error", err.Error())
		return fault.Unavailable("trail_unreadable",
			"the audit trail on this host could not be read")
	}

	view := tailView{
		Events:  make([]eventView, 0, len(events)),
		Limit:   limit,
		Max:     audit.MaxTail,
		Shipped: m.shipped,
	}
	for _, e := range events {
		view.Events = append(view.Events, eventView{
			At:        e.At.UTC().Format("2006-01-02T15:04:05Z"),
			Action:    e.Action,
			Outcome:   e.Outcome,
			ActorID:   e.ActorID,
			ActorName: e.ActorName,
			Object:    e.Object,
			Reason:    e.Reason,
			Fields:    e.Fields,
		})
	}

	httpx.Write(w, http.StatusOK, view)
	return nil
}

func limitOf(r *http.Request) (int, error) {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return defaultLimit, nil
	}

	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 1 {
		return 0, fault.Invalid("invalid_limit", "limit must be a positive whole number")
	}
	if limit > audit.MaxTail {
		return 0, fault.Invalid("invalid_limit",
			"limit must be at most "+strconv.Itoa(audit.MaxTail))
	}
	return limit, nil
}
