package target

import (
	"net/http"
	"time"

	"github.com/marstack-labs/marstack-access/internal/kernel/httpx"
)

type registerRequest struct {
	Name       string   `json:"name"`
	Address    string   `json:"address"`
	Port       int      `json:"port"`
	Principals []string `json:"principals"`
}

type targetView struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Address    string   `json:"address"`
	Port       int      `json:"port"`
	Principals []string `json:"principals"`
	CreatedAt  string   `json:"created_at"`
}

type targetListView struct {
	Targets []targetView `json:"targets"`
}

func viewOf(t Target) targetView {
	return targetView{
		ID:         t.ID,
		Name:       t.Name,
		Address:    t.Address,
		Port:       t.Port,
		Principals: t.Principals,
		CreatedAt:  t.CreatedAt.UTC().Format(time.RFC3339),
	}
}

func (m *Module) handleRegister(w http.ResponseWriter, r *http.Request) error {
	req, err := httpx.Decode[registerRequest](w, r)
	if err != nil {
		return err
	}

	t, err := m.service.register(r.Context(), RegisterInput(req))
	if err != nil {
		return err
	}

	httpx.Write(w, http.StatusCreated, viewOf(t))
	return nil
}

func (m *Module) handleList(w http.ResponseWriter, r *http.Request) error {
	targets, err := m.service.list(r.Context())
	if err != nil {
		return err
	}

	views := make([]targetView, 0, len(targets))
	for _, t := range targets {
		views = append(views, viewOf(t))
	}

	httpx.Write(w, http.StatusOK, targetListView{Targets: views})
	return nil
}

func (m *Module) handleGet(w http.ResponseWriter, r *http.Request) error {
	t, err := m.service.get(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	}

	httpx.Write(w, http.StatusOK, viewOf(t))
	return nil
}

func (m *Module) handleDelete(w http.ResponseWriter, r *http.Request) error {
	if err := m.service.remove(r.Context(), r.PathValue("id")); err != nil {
		return err
	}

	httpx.Write(w, http.StatusNoContent, nil)
	return nil
}
