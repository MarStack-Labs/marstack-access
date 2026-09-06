package approval

import (
	"context"
	"net/http"
	"time"

	"github.com/marstack-labs/marstack-access/internal/kernel/audit"
	"github.com/marstack-labs/marstack-access/internal/kernel/authz"
	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
	"github.com/marstack-labs/marstack-access/internal/kernel/httpx"
)

type createRequestBody struct {
	TargetID  string `json:"target_id"`
	Principal string `json:"principal"`
	Reason    string `json:"reason"`
	TTL       string `json:"ttl"`
}

type grantQueryBody struct {
	UserID    string `json:"user_id"`
	TargetID  string `json:"target_id"`
	Principal string `json:"principal"`
}

type requestView struct {
	ID             string `json:"id"`
	RequesterID    string `json:"requester_id"`
	TargetID       string `json:"target_id"`
	Principal      string `json:"principal"`
	Reason         string `json:"reason"`
	State          string `json:"state"`
	GrantTTL       string `json:"grant_ttl"`
	CreatedAt      string `json:"created_at"`
	RequestExpires string `json:"request_expires_at"`
	DecidedBy      string `json:"decided_by,omitempty"`
	DecidedAt      string `json:"decided_at,omitempty"`
	GrantExpires   string `json:"grant_expires_at,omitempty"`
}

type requestListView struct {
	Requests []requestView `json:"requests"`
}

type grantView struct {
	Active    bool   `json:"active"`
	RequestID string `json:"request_id,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

func (m *Module) viewOf(r Request) requestView {
	view := requestView{
		ID:             r.ID,
		RequesterID:    r.RequesterID,
		TargetID:       r.TargetID,
		Principal:      r.Principal,
		Reason:         r.Reason,
		State:          r.effectiveState(m.service.now()),
		GrantTTL:       r.GrantTTL.String(),
		CreatedAt:      r.CreatedAt.UTC().Format(time.RFC3339),
		RequestExpires: r.RequestExpiresAt.UTC().Format(time.RFC3339),
		DecidedBy:      r.DecidedBy,
	}
	if !r.DecidedAt.IsZero() {
		view.DecidedAt = r.DecidedAt.UTC().Format(time.RFC3339)
	}
	if !r.GrantExpiresAt.IsZero() {
		view.GrantExpires = r.GrantExpiresAt.UTC().Format(time.RFC3339)
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

func (m *Module) handleCreate(w http.ResponseWriter, r *http.Request) error {
	caller, err := callerOf(r)
	if err != nil {
		return err
	}

	body, err := httpx.Decode[createRequestBody](w, r)
	if err != nil {
		return err
	}

	ttl, err := parseTTL(body.TTL)
	if err != nil {
		return err
	}

	req, err := m.service.create(r.Context(), caller, CreateInput{
		TargetID:  body.TargetID,
		Principal: body.Principal,
		Reason:    body.Reason,
		GrantTTL:  ttl,
	})
	if err != nil {
		return err
	}

	m.emit(r.Context(), "request.raised", req.ID, map[string]string{
		"target":    req.TargetID,
		"principal": req.Principal,
		"reason":    req.Reason,
		"grant_ttl": req.GrantTTL.String(),
	})

	httpx.Write(w, http.StatusCreated, m.viewOf(req))
	return nil
}

func parseTTL(value string) (time.Duration, error) {
	if value == "" {
		return 0, nil
	}
	ttl, err := time.ParseDuration(value)
	if err != nil {
		return 0, fault.Invalid("invalid_ttl", "ttl must be a duration such as 2h or 30m")
	}
	return ttl, nil
}

func (m *Module) handleList(w http.ResponseWriter, r *http.Request) error {
	caller, err := callerOf(r)
	if err != nil {
		return err
	}

	requests, err := m.service.list(r.Context(), caller)
	if err != nil {
		return err
	}

	views := make([]requestView, 0, len(requests))
	for _, req := range requests {
		views = append(views, m.viewOf(req))
	}

	httpx.Write(w, http.StatusOK, requestListView{Requests: views})
	return nil
}

func (m *Module) handleGet(w http.ResponseWriter, r *http.Request) error {
	caller, err := callerOf(r)
	if err != nil {
		return err
	}

	req, err := m.service.get(r.Context(), caller, r.PathValue("id"))
	if err != nil {
		return err
	}

	httpx.Write(w, http.StatusOK, m.viewOf(req))
	return nil
}

func (m *Module) handleApprove(w http.ResponseWriter, r *http.Request) error {
	return m.decide(w, r, m.service.approve, "request.approved", audit.OutcomeAllowed)
}

func (m *Module) handleDeny(w http.ResponseWriter, r *http.Request) error {
	return m.decide(w, r, m.service.deny, "request.denied", audit.OutcomeDenied)
}

func (m *Module) handleCancel(w http.ResponseWriter, r *http.Request) error {
	return m.decide(w, r, m.service.cancel, "request.cancelled", audit.OutcomeDenied)
}

type decider func(ctx context.Context, caller authz.Identity, id string) (Request, error)

func (m *Module) decide(w http.ResponseWriter, r *http.Request, fn decider,
	action, outcome string) error {
	caller, err := callerOf(r)
	if err != nil {
		return err
	}

	req, err := fn(r.Context(), caller, r.PathValue("id"))
	if err != nil {
		return err
	}

	fields := map[string]string{
		"requester": req.RequesterID,
		"target":    req.TargetID,
		"principal": req.Principal,
	}
	if !req.GrantExpiresAt.IsZero() {
		fields["expires"] = req.GrantExpiresAt.UTC().Format(time.RFC3339)
	}

	authz.Emit(r.Context(), m.trail, m.log, audit.Event{
		Action:  action,
		Outcome: outcome,
		Object:  req.ID,
		Reason:  req.Reason,
		Fields:  fields,
	})

	httpx.Write(w, http.StatusOK, m.viewOf(req))
	return nil
}

func (m *Module) handleGrant(w http.ResponseWriter, r *http.Request) error {
	body, err := httpx.Decode[grantQueryBody](w, r)
	if err != nil {
		return err
	}

	g, err := m.service.grant(r.Context(), GrantQuery(body))
	if err != nil {
		return err
	}

	view := grantView{Active: g.Active, RequestID: g.RequestID, Reason: g.Reason}
	if !g.ExpiresAt.IsZero() {
		view.ExpiresAt = g.ExpiresAt.UTC().Format(time.RFC3339)
	}

	httpx.Write(w, http.StatusOK, view)
	return nil
}
