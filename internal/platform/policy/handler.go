package policy

import (
	"net/http"
	"time"

	"github.com/marstack-labs/marstack-access/internal/kernel/httpx"
)

type createRequest struct {
	Name        string   `json:"name"`
	SubjectKind string   `json:"subject_kind"`
	SubjectID   string   `json:"subject_id"`
	TargetID    string   `json:"target_id"`
	Principals  []string `json:"principals"`
}

type evaluateRequest struct {
	UserID    string `json:"user_id"`
	Role      string `json:"role"`
	TargetID  string `json:"target_id"`
	Principal string `json:"principal"`
}

type policyView struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	SubjectKind string   `json:"subject_kind"`
	SubjectID   string   `json:"subject_id"`
	TargetID    string   `json:"target_id"`
	Principals  []string `json:"principals"`
	CreatedAt   string   `json:"created_at"`
}

type policyListView struct {
	Policies []policyView `json:"policies"`
}

type decisionView struct {
	Allowed  bool   `json:"allowed"`
	PolicyID string `json:"policy_id,omitempty"`
	Reason   string `json:"reason"`
}

func viewOf(p Policy) policyView {
	return policyView{
		ID:          p.ID,
		Name:        p.Name,
		SubjectKind: p.SubjectKind,
		SubjectID:   p.SubjectID,
		TargetID:    p.TargetID,
		Principals:  p.Principals,
		CreatedAt:   p.CreatedAt.UTC().Format(time.RFC3339),
	}
}

func (m *Module) handleCreate(w http.ResponseWriter, r *http.Request) error {
	req, err := httpx.Decode[createRequest](w, r)
	if err != nil {
		return err
	}

	p, err := m.service.create(r.Context(), CreateInput(req))
	if err != nil {
		return err
	}

	httpx.Write(w, http.StatusCreated, viewOf(p))
	return nil
}

func (m *Module) handleList(w http.ResponseWriter, r *http.Request) error {
	policies, err := m.service.list(r.Context())
	if err != nil {
		return err
	}

	views := make([]policyView, 0, len(policies))
	for _, p := range policies {
		views = append(views, viewOf(p))
	}

	httpx.Write(w, http.StatusOK, policyListView{Policies: views})
	return nil
}

func (m *Module) handleGet(w http.ResponseWriter, r *http.Request) error {
	p, err := m.service.get(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	}

	httpx.Write(w, http.StatusOK, viewOf(p))
	return nil
}

func (m *Module) handleDelete(w http.ResponseWriter, r *http.Request) error {
	if err := m.service.remove(r.Context(), r.PathValue("id")); err != nil {
		return err
	}

	httpx.Write(w, http.StatusNoContent, nil)
	return nil
}

func (m *Module) handleEvaluate(w http.ResponseWriter, r *http.Request) error {
	req, err := httpx.Decode[evaluateRequest](w, r)
	if err != nil {
		return err
	}

	decision, err := m.service.evaluate(r.Context(), Request(req))
	if err != nil {
		return err
	}

	httpx.Write(w, http.StatusOK, decisionView(decision))
	return nil
}
