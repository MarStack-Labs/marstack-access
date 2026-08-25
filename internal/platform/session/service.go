package session

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/marstack-labs/marstack-access/internal/kernel/authz"
	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
	"github.com/marstack-labs/marstack-access/internal/kernel/ids"
)

type service struct {
	repo       *repository
	terminator Terminator
	log        *slog.Logger
	now        func() time.Time
}

func (s *service) open(ctx context.Context, in OpenInput) error {
	if err := checkOpenInput(in); err != nil {
		return err
	}

	record := Session{
		ID:           in.ID,
		UserID:       in.UserID,
		UserName:     in.UserName,
		TargetID:     in.TargetID,
		TargetName:   in.TargetName,
		Principal:    in.Principal,
		CredentialID: in.CredentialID,
		RemoteAddr:   in.RemoteAddr,
		Recording:    in.Recording,
		StartedAt:    s.now(),
	}

	if err := s.repo.insert(ctx, record); err != nil {
		return fault.Internal(err)
	}
	return nil
}

func checkOpenInput(in OpenInput) error {
	if !ids.HasPrefix(in.ID, idPrefix) {
		return fault.Invalid("invalid_id", "a session id looks like "+idPrefix+"-<random>")
	}
	if !ids.HasPrefix(in.UserID, userIDPrefix) {
		return fault.Invalid("invalid_user_id", "a user id looks like "+userIDPrefix+"-<random>")
	}
	if !ids.HasPrefix(in.TargetID, targetIDPrefix) {
		return fault.Invalid("invalid_target_id", "a target id looks like "+targetIDPrefix+"-<random>")
	}
	if in.Principal == "" {
		return fault.Invalid("invalid_principal", "a principal is required")
	}
	if in.Recording == "" {
		return fault.Invalid("invalid_recording",
			"a recording path is required: a session row with no recording is an index to nothing")
	}
	return nil
}

func (s *service) close(ctx context.Context, id string, in CloseInput) error {
	if !ids.HasPrefix(id, idPrefix) {
		return fault.Invalid("invalid_id", "a session id looks like "+idPrefix+"-<random>")
	}
	in.Reason = trimReason(in.Reason)

	finished, err := s.repo.finish(ctx, id, s.now(), in)
	switch {
	case err != nil:
		return fault.Internal(err)
	case !finished:
		return fault.Conflict("not_open", "no open session with that id")
	}
	return nil
}

func (s *service) reconcile(ctx context.Context) error {
	closed, err := s.repo.closeDangling(ctx, s.now(), ReasonGatewayRestarted)
	if err != nil {
		return fault.Internal(err)
	}
	if closed > 0 {
		s.log.Warn("closed sessions left open by an earlier run",
			"count", closed, "reason", ReasonGatewayRestarted)
	}
	return nil
}

func (s *service) get(ctx context.Context, caller authz.Identity, id string) (Session, error) {
	if !ids.HasPrefix(id, idPrefix) {
		return Session{}, fault.Invalid("invalid_id", "a session id looks like "+idPrefix+"-<random>")
	}

	record, err := s.repo.get(ctx, id)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Session{}, notFound()
	case err != nil:
		return Session{}, fault.Internal(err)
	}

	if caller.Role != authz.RoleAdmin && record.UserID != caller.UserID {
		return Session{}, notFound()
	}
	return record, nil
}

func (s *service) list(ctx context.Context, caller authz.Identity) ([]Session, error) {
	scope := caller.UserID
	if caller.Role == authz.RoleAdmin {
		scope = ""
	}

	sessions, err := s.repo.list(ctx, scope)
	if err != nil {
		return nil, fault.Internal(err)
	}
	return sessions, nil
}

func (s *service) kill(ctx context.Context, caller authz.Identity, id string) (Session, bool, error) {
	record, err := s.get(ctx, caller, id)
	if err != nil {
		return Session{}, false, err
	}

	if !record.active() {
		return Session{}, false, fault.Conflict("not_active",
			"this session already ended at "+record.EndedAt.UTC().Format(time.RFC3339))
	}

	if s.terminator == nil {
		return Session{}, false, fault.Unavailable("no_data_plane",
			"this node runs no data plane, so it holds no socket to close")
	}

	killed := s.terminator.Kill(id)
	if !killed {
		s.log.Warn("kill found no live session",
			"session", id, "by", caller.Name)
		return record, false, nil
	}

	s.log.Warn("session killed", "session", id, "by", caller.Name, "user", record.UserName,
		"target", record.TargetName, "principal", record.Principal)

	return record, true, nil
}

func notFound() error {
	return fault.NotFound("session_not_found", "no session with that id exists")
}

func trimReason(reason string) string {
	trimmed := strings.TrimSpace(reason)
	if len(trimmed) > maxReasonLen {
		return trimmed[:maxReasonLen]
	}
	return trimmed
}
