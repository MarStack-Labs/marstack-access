package approval

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/marstack-labs/marstack-access/internal/kernel/authz"
	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
	"github.com/marstack-labs/marstack-access/internal/kernel/ids"
	"github.com/marstack-labs/marstack-access/internal/kernel/validate"
)

type Policies interface {
	Authorize(ctx context.Context, id authz.Identity, targetID, principal string) error
}

type service struct {
	repo     *repository
	policies Policies
	now      func() time.Time
}

func (s *service) create(ctx context.Context, requester authz.Identity, in CreateInput) (Request, error) {
	if !ids.HasPrefix(in.TargetID, targetIDPrefix) {
		return Request{}, fault.Invalid("invalid_target_id",
			"a target id looks like "+targetIDPrefix+"-<random>")
	}
	if err := validate.Principal("principal", in.Principal); err != nil {
		return Request{}, err
	}
	if err := checkReason(in.Reason); err != nil {
		return Request{}, err
	}

	ttl := in.GrantTTL
	if ttl == 0 {
		ttl = defaultGrantTTL
	}
	if ttl < 0 || ttl > maxGrantTTL {
		return Request{}, fault.Invalid("invalid_ttl",
			fmt.Sprintf("ttl must be between 0 and %s", maxGrantTTL))
	}

	if err := s.policies.Authorize(ctx, requester, in.TargetID, in.Principal); err != nil {
		return Request{}, err
	}

	now := s.now()
	req := Request{
		ID:               ids.New(idPrefix),
		RequesterID:      requester.UserID,
		TargetID:         in.TargetID,
		Principal:        in.Principal,
		Reason:           in.Reason,
		State:            StatePending,
		GrantTTL:         ttl,
		CreatedAt:        now,
		RequestExpiresAt: now.Add(pendingWindow),
	}

	if err := s.repo.insert(ctx, req); err != nil {
		return Request{}, fault.Internal(err)
	}
	return req, nil
}

func checkReason(reason string) error {
	trimmed := strings.TrimSpace(reason)
	if trimmed == "" {
		return fault.Invalid("invalid_reason",
			"a reason is required: it is the only part of the record a later reader cannot reconstruct")
	}
	if len(trimmed) > maxReasonLen {
		return fault.Invalid("invalid_reason",
			fmt.Sprintf("a reason must be at most %d characters", maxReasonLen))
	}
	return nil
}

func (s *service) get(ctx context.Context, caller authz.Identity, id string) (Request, error) {
	if !ids.HasPrefix(id, idPrefix) {
		return Request{}, fault.Invalid("invalid_id", "a request id looks like "+idPrefix+"-<random>")
	}

	req, err := s.repo.get(ctx, id)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Request{}, notFound()
	case err != nil:
		return Request{}, fault.Internal(err)
	}

	if !s.mayRead(caller, req) {
		return Request{}, notFound()
	}
	return req, nil
}

func (s *service) mayRead(caller authz.Identity, req Request) bool {
	return caller.Role == authz.RoleAdmin || req.RequesterID == caller.UserID
}

func (s *service) list(ctx context.Context, caller authz.Identity) ([]Request, error) {
	scope := caller.UserID
	if caller.Role == authz.RoleAdmin {
		scope = ""
	}

	requests, err := s.repo.list(ctx, scope)
	if err != nil {
		return nil, fault.Internal(err)
	}
	return requests, nil
}

func (s *service) approve(ctx context.Context, approver authz.Identity, id string) (Request, error) {
	return s.decide(ctx, approver, id, StateApproved)
}

func (s *service) deny(ctx context.Context, approver authz.Identity, id string) (Request, error) {
	return s.decide(ctx, approver, id, StateDenied)
}

func (s *service) decide(ctx context.Context, approver authz.Identity, id, state string) (Request, error) {
	req, err := s.get(ctx, approver, id)
	if err != nil {
		return Request{}, err
	}

	if req.RequesterID == approver.UserID {
		return Request{}, fault.Forbidden("self_approval",
			"a request cannot be decided by the account that raised it")
	}

	now := s.now()
	if effective := req.effectiveState(now); effective != StatePending {
		return Request{}, fault.Conflict("not_pending",
			"this request is "+effective+" and can no longer be decided")
	}

	var grantExpiresAt time.Time
	if state == StateApproved {
		grantExpiresAt = now.Add(req.GrantTTL)
	}

	decided, err := s.repo.decide(ctx, id, state, approver.UserID, now, grantExpiresAt)
	switch {
	case err != nil:
		return Request{}, fault.Internal(err)
	case !decided:
		return Request{}, fault.Conflict("not_pending",
			"this request was decided by someone else first")
	}

	req.State = state
	req.DecidedBy = approver.UserID
	req.DecidedAt = now
	req.GrantExpiresAt = grantExpiresAt
	return req, nil
}

func (s *service) cancel(ctx context.Context, caller authz.Identity, id string) (Request, error) {
	req, err := s.get(ctx, caller, id)
	if err != nil {
		return Request{}, err
	}
	if req.RequesterID != caller.UserID {
		return Request{}, fault.Forbidden("not_the_requester",
			"only the account that raised a request may cancel it")
	}

	now := s.now()
	if effective := req.effectiveState(now); effective != StatePending {
		return Request{}, fault.Conflict("not_pending",
			"this request is "+effective+" and can no longer be cancelled")
	}

	cancelled, err := s.repo.decide(ctx, id, StateCancelled, caller.UserID, now, time.Time{})
	switch {
	case err != nil:
		return Request{}, fault.Internal(err)
	case !cancelled:
		return Request{}, fault.Conflict("not_pending", "this request was already decided")
	}

	req.State = StateCancelled
	req.DecidedBy = caller.UserID
	req.DecidedAt = now
	return req, nil
}

func (s *service) grant(ctx context.Context, q GrantQuery) (Grant, error) {
	if !ids.HasPrefix(q.UserID, userIDPrefix) {
		return Grant{}, fault.Invalid("invalid_user_id",
			"a user id looks like "+userIDPrefix+"-<random>")
	}
	if !ids.HasPrefix(q.TargetID, targetIDPrefix) {
		return Grant{}, fault.Invalid("invalid_target_id",
			"a target id looks like "+targetIDPrefix+"-<random>")
	}
	if err := validate.Principal("principal", q.Principal); err != nil {
		return Grant{}, err
	}

	now := s.now()

	req, err := s.repo.activeGrant(ctx, q, now)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Grant{Active: false}, nil
	case err != nil:
		return Grant{}, fault.Internal(err)
	}

	if !req.grantsAccess(now) {
		return Grant{Active: false}, nil
	}

	return Grant{
		Active:    true,
		RequestID: req.ID,
		ExpiresAt: req.GrantExpiresAt,
		Reason:    req.Reason,
	}, nil
}

func (s *service) HasGrant(ctx context.Context, userID, targetID, principal string) error {
	g, err := s.grant(ctx, GrantQuery{UserID: userID, TargetID: targetID, Principal: principal})
	if err != nil {
		return err
	}
	if !g.Active {
		return fault.Forbidden("no_grant",
			"no approved and unexpired request grants this principal on this target")
	}
	return nil
}

func notFound() error {
	return fault.NotFound("request_not_found", "no access request with that id exists")
}
