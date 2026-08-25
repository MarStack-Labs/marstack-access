package target

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
	"github.com/marstack-labs/marstack-access/internal/kernel/ids"
	"github.com/marstack-labs/marstack-access/internal/kernel/validate"
)

type service struct {
	repo *repository
	now  func() time.Time
}

func (s *service) register(ctx context.Context, in RegisterInput) (Target, error) {
	if in.Port == 0 {
		in.Port = defaultPort
	}

	principals, err := s.checkInput(in)
	if err != nil {
		return Target{}, err
	}

	t := Target{
		ID:         ids.New(idPrefix),
		Name:       in.Name,
		Address:    in.Address,
		Port:       in.Port,
		Principals: principals,
		CreatedAt:  s.now(),
	}

	switch err := s.repo.insert(ctx, t); {
	case errors.Is(err, errNameTaken):
		return Target{}, fault.Conflict("target_name_taken", "a target with that name is already registered")
	case err != nil:
		return Target{}, fault.Internal(err)
	}

	return t, nil
}

func (s *service) checkInput(in RegisterInput) ([]string, error) {
	if err := validate.Name("name", in.Name); err != nil {
		return nil, err
	}
	if err := validate.Address("address", in.Address); err != nil {
		return nil, err
	}
	if err := validate.Port("port", in.Port); err != nil {
		return nil, err
	}
	return s.checkPrincipals(in.Principals)
}

func (s *service) checkPrincipals(principals []string) ([]string, error) {
	if len(principals) == 0 {
		return nil, fault.Invalid("invalid_principals",
			"at least one principal is required, otherwise no session can ever land on this target")
	}
	if len(principals) > maxPrincipals {
		return nil, fault.Invalid("invalid_principals",
			fmt.Sprintf("at most %d principals are allowed", maxPrincipals))
	}

	for _, principal := range principals {
		if err := validate.Principal("principals", principal); err != nil {
			return nil, err
		}
	}

	unique := slices.Clone(principals)
	slices.Sort(unique)
	return slices.Compact(unique), nil
}

func (s *service) get(ctx context.Context, id string) (Target, error) {
	if err := s.checkID(id); err != nil {
		return Target{}, err
	}

	t, err := s.repo.get(ctx, id)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Target{}, notFound()
	case err != nil:
		return Target{}, fault.Internal(err)
	}
	return t, nil
}

func (s *service) list(ctx context.Context) ([]Target, error) {
	targets, err := s.repo.list(ctx)
	if err != nil {
		return nil, fault.Internal(err)
	}
	return targets, nil
}

func (s *service) remove(ctx context.Context, id string) error {
	if err := s.checkID(id); err != nil {
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

func (s *service) checkID(id string) error {
	if !ids.HasPrefix(id, idPrefix) {
		return fault.Invalid("invalid_id", "a target id looks like "+idPrefix+"-<random>")
	}
	return nil
}

func notFound() error {
	return fault.NotFound("target_not_found", "no target with that id is registered")
}

func (s *service) getByName(ctx context.Context, name string) (Target, error) {
	if err := validate.Name("name", name); err != nil {
		return Target{}, err
	}

	t, err := s.repo.getByName(ctx, name)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Target{}, fault.NotFound("target_not_found", "no target with that name is registered")
	case err != nil:
		return Target{}, fault.Internal(err)
	}
	return t, nil
}
