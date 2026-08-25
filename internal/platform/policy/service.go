package policy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/marstack-labs/marstack-access/internal/kernel/authz"
	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
	"github.com/marstack-labs/marstack-access/internal/kernel/ids"
	"github.com/marstack-labs/marstack-access/internal/kernel/validate"
)

type Targets interface {
	Principals(ctx context.Context, targetID string) ([]string, error)
}

type service struct {
	repo    *repository
	targets Targets
	now     func() time.Time
}

func (s *service) create(ctx context.Context, in CreateInput) (Policy, error) {
	if err := validate.Name("name", in.Name); err != nil {
		return Policy{}, err
	}
	if err := validate.OneOf("subject_kind", in.SubjectKind, subjectKinds...); err != nil {
		return Policy{}, err
	}
	if err := s.checkSubject(in); err != nil {
		return Policy{}, err
	}
	if !ids.HasPrefix(in.TargetID, targetIDPrefix) {
		return Policy{}, fault.Invalid("invalid_target_id",
			"a target id looks like "+targetIDPrefix+"-<random>")
	}

	principals, err := s.checkPrincipals(ctx, in)
	if err != nil {
		return Policy{}, err
	}

	p := Policy{
		ID:          ids.New(idPrefix),
		Name:        in.Name,
		SubjectKind: in.SubjectKind,
		SubjectID:   in.SubjectID,
		TargetID:    in.TargetID,
		Principals:  principals,
		CreatedAt:   s.now(),
	}

	switch err := s.repo.insert(ctx, p); {
	case errors.Is(err, errNameTaken):
		return Policy{}, fault.Conflict("policy_name_taken", "a policy with that name already exists")
	case err != nil:
		return Policy{}, fault.Internal(err)
	}

	return p, nil
}

func (s *service) checkSubject(in CreateInput) error {
	switch in.SubjectKind {
	case SubjectUser:
		if !ids.HasPrefix(in.SubjectID, userIDPrefix) {
			return fault.Invalid("invalid_subject_id",
				"a user subject id looks like "+userIDPrefix+"-<random>")
		}
	case SubjectRole:
		if err := validate.OneOf("subject_id", in.SubjectID, authz.Roles()...); err != nil {
			return err
		}
	}
	return nil
}

func (s *service) checkPrincipals(ctx context.Context, in CreateInput) ([]string, error) {
	if len(in.Principals) == 0 {
		return nil, fault.Invalid("invalid_principals",
			"at least one principal is required, otherwise the policy grants nothing")
	}
	if len(in.Principals) > maxPrincipals {
		return nil, fault.Invalid("invalid_principals",
			fmt.Sprintf("at most %d principals are allowed", maxPrincipals))
	}
	for _, principal := range in.Principals {
		if err := validate.Principal("principals", principal); err != nil {
			return nil, err
		}
	}

	accepted, err := s.targets.Principals(ctx, in.TargetID)
	if err != nil {
		return nil, err
	}

	unique := slices.Clone(in.Principals)
	slices.Sort(unique)
	unique = slices.Compact(unique)

	for _, principal := range unique {
		if !slices.Contains(accepted, principal) {
			return nil, fault.Invalid("principal_not_accepted",
				fmt.Sprintf("the target does not accept the principal %q", principal))
		}
	}

	return unique, nil
}

func (s *service) get(ctx context.Context, id string) (Policy, error) {
	if !ids.HasPrefix(id, idPrefix) {
		return Policy{}, fault.Invalid("invalid_id", "a policy id looks like "+idPrefix+"-<random>")
	}

	p, err := s.repo.get(ctx, id)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Policy{}, notFound()
	case err != nil:
		return Policy{}, fault.Internal(err)
	}
	return p, nil
}

func (s *service) list(ctx context.Context) ([]Policy, error) {
	policies, err := s.repo.list(ctx)
	if err != nil {
		return nil, fault.Internal(err)
	}
	return policies, nil
}

func (s *service) remove(ctx context.Context, id string) error {
	if _, err := s.get(ctx, id); err != nil {
		return err
	}

	deleted, err := s.repo.delete(ctx, id)
	switch {
	case err != nil:
		return fault.Internal(err)
	case !deleted:
		return notFound()
	}
	return nil
}

func (s *service) evaluate(ctx context.Context, req Request) (Decision, error) {
	if !ids.HasPrefix(req.UserID, userIDPrefix) {
		return Decision{}, fault.Invalid("invalid_user_id",
			"a user id looks like "+userIDPrefix+"-<random>")
	}
	if !ids.HasPrefix(req.TargetID, targetIDPrefix) {
		return Decision{}, fault.Invalid("invalid_target_id",
			"a target id looks like "+targetIDPrefix+"-<random>")
	}
	if err := validate.Principal("principal", req.Principal); err != nil {
		return Decision{}, err
	}
	if req.Role != "" {
		if err := validate.OneOf("role", req.Role, authz.Roles()...); err != nil {
			return Decision{}, err
		}
	}

	id, err := s.repo.matching(ctx, req)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Decision{
			Allowed: false,
			Reason:  "no policy grants this user the requested principal on this target",
		}, nil
	case err != nil:
		return Decision{}, fault.Internal(err)
	}

	return Decision{Allowed: true, PolicyID: id, Reason: "granted by policy " + id}, nil
}

func (s *service) Authorize(ctx context.Context, id authz.Identity, targetID, principal string) error {
	decision, err := s.evaluate(ctx, Request{
		UserID:    id.UserID,
		Role:      id.Role,
		TargetID:  targetID,
		Principal: principal,
	})
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return fault.Forbidden("no_policy", decision.Reason)
	}
	return nil
}

func notFound() error {
	return fault.NotFound("policy_not_found", "no policy with that id exists")
}
