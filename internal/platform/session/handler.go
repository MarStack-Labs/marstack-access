package session

import (
	"net/http"
	"time"

	"github.com/marstack-labs/marstack-access/internal/kernel/audit"
	"github.com/marstack-labs/marstack-access/internal/kernel/authz"
	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
	"github.com/marstack-labs/marstack-access/internal/kernel/httpx"
)

type sessionView struct {
	ID            string `json:"id"`
	Active        bool   `json:"active"`
	UserID        string `json:"user_id"`
	UserName      string `json:"user_name"`
	TargetID      string `json:"target_id"`
	TargetName    string `json:"target_name"`
	Principal     string `json:"principal"`
	CredentialID  string `json:"credential_id"`
	RemoteAddr    string `json:"remote_addr"`
	Recording     string `json:"recording"`
	StartedAt     string `json:"started_at"`
	EndedAt       string `json:"ended_at,omitempty"`
	ExitCode      *int   `json:"exit_code,omitempty"`
	Reason        string `json:"reason,omitempty"`
	RecordedBytes int64  `json:"recorded_bytes"`
}

type sessionListView struct {
	Sessions []sessionView `json:"sessions"`
}

type killView struct {
	Killed  bool        `json:"killed"`
	Session sessionView `json:"session"`
	Note    string      `json:"note,omitempty"`
}

func viewOf(s Session) sessionView {
	view := sessionView{
		ID:            s.ID,
		Active:        s.active(),
		UserID:        s.UserID,
		UserName:      s.UserName,
		TargetID:      s.TargetID,
		TargetName:    s.TargetName,
		Principal:     s.Principal,
		CredentialID:  s.CredentialID,
		RemoteAddr:    s.RemoteAddr,
		Recording:     s.Recording,
		StartedAt:     s.StartedAt.UTC().Format(time.RFC3339),
		Reason:        s.Reason,
		RecordedBytes: s.RecordedBytes,
	}
	if !s.EndedAt.IsZero() {
		view.EndedAt = s.EndedAt.UTC().Format(time.RFC3339)
		code := s.ExitCode
		view.ExitCode = &code
	}
	return view
}

func callerOf(r *http.Request) (authz.Identity, error) {
	id, ok := authz.IdentityFrom(r.Context())
	if !ok {
		return authz.Identity{}, fault.Internal(errUnauthenticatedRoute)
	}
	return id, nil
}

func (m *Module) handleList(w http.ResponseWriter, r *http.Request) error {
	caller, err := callerOf(r)
	if err != nil {
		return err
	}

	sessions, err := m.service.list(r.Context(), caller)
	if err != nil {
		return err
	}

	views := make([]sessionView, 0, len(sessions))
	for _, s := range sessions {
		views = append(views, viewOf(s))
	}

	httpx.Write(w, http.StatusOK, sessionListView{Sessions: views})
	return nil
}

func (m *Module) handleGet(w http.ResponseWriter, r *http.Request) error {
	caller, err := callerOf(r)
	if err != nil {
		return err
	}

	record, err := m.service.get(r.Context(), caller, r.PathValue("id"))
	if err != nil {
		return err
	}

	httpx.Write(w, http.StatusOK, viewOf(record))
	return nil
}

func (m *Module) handleKill(w http.ResponseWriter, r *http.Request) error {
	caller, err := callerOf(r)
	if err != nil {
		return err
	}

	record, killed, err := m.service.kill(r.Context(), caller, r.PathValue("id"))
	if err != nil {
		return err
	}

	outcome := audit.OutcomeAllowed
	if !killed {
		outcome = audit.OutcomeError
	}
	authz.Emit(r.Context(), m.trail, m.log, audit.Event{
		Action:  "session.killed",
		Outcome: outcome,
		Object:  record.ID,
		Fields: map[string]string{
			"user":      record.UserName,
			"target":    record.TargetName,
			"principal": record.Principal,
			"recording": record.Recording,
		},
	})

	view := killView{Killed: killed, Session: viewOf(record)}
	if !killed {
		view.Note = "the row is open but no socket for it is held here, so it was opened by another node or by a run that has since stopped"
	}

	httpx.Write(w, http.StatusOK, view)
	return nil
}
