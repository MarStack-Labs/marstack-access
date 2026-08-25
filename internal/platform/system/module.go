package system

import (
	"log/slog"
	"net/http"

	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
	"github.com/marstack-labs/marstack-access/internal/kernel/httpx"
	"github.com/marstack-labs/marstack-access/internal/store"
	"github.com/marstack-labs/marstack-access/internal/version"
)

type Module struct {
	store *store.Store
	log   *slog.Logger
}

func New(st *store.Store, log *slog.Logger) *Module {
	return &Module{store: st, log: log}
}

func (m *Module) Name() string {
	return "system"
}

func (m *Module) Migrations() []store.Migration {
	return nil
}

func (m *Module) Routes(mux *http.ServeMux) {
	mux.Handle("GET /healthz", httpx.Wrap(m.log, m.handleHealthz))
	mux.Handle("GET /v1/version", httpx.Wrap(m.log, m.handleVersion))
}

func (m *Module) handleHealthz(w http.ResponseWriter, r *http.Request) error {
	if err := m.store.Ping(r.Context()); err != nil {
		return fault.Unavailable("store_unavailable", "the control plane store is not reachable")
	}
	httpx.Write(w, http.StatusOK, map[string]string{"status": "ok"})
	return nil
}

func (m *Module) handleVersion(w http.ResponseWriter, _ *http.Request) error {
	httpx.Write(w, http.StatusOK, map[string]string{
		"version": version.Version,
		"commit":  version.Commit,
	})
	return nil
}
