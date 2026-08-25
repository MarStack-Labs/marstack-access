package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/marstack-labs/marstack-access/internal/kernel/authz"
	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
	"github.com/marstack-labs/marstack-access/internal/kernel/ids"
	"github.com/marstack-labs/marstack-access/internal/kernel/validate"
)

const selectorAttempts = 8

type service struct {
	repo *repository
	now  func() time.Time
}

func (s *service) createUser(ctx context.Context, in CreateUserInput) (User, error) {
	if err := validate.Name("name", in.Name); err != nil {
		return User{}, err
	}
	if err := validate.OneOf("role", in.Role, authz.Roles()...); err != nil {
		return User{}, err
	}

	u := User{
		ID:        ids.New(userIDPrefix),
		Name:      in.Name,
		Role:      in.Role,
		CreatedAt: s.now(),
	}

	switch err := s.repo.insertUser(ctx, u); {
	case errors.Is(err, errNameTaken):
		return User{}, fault.Conflict("user_name_taken", "a user with that name already exists")
	case err != nil:
		return User{}, fault.Internal(err)
	}

	return u, nil
}

func (s *service) getUser(ctx context.Context, id string) (User, error) {
	if !ids.HasPrefix(id, userIDPrefix) {
		return User{}, fault.Invalid("invalid_id", "a user id looks like "+userIDPrefix+"-<random>")
	}

	u, err := s.repo.getUser(ctx, id)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return User{}, userNotFound()
	case err != nil:
		return User{}, fault.Internal(err)
	}
	return u, nil
}

func (s *service) listUsers(ctx context.Context) ([]User, error) {
	users, err := s.repo.listUsers(ctx)
	if err != nil {
		return nil, fault.Internal(err)
	}
	return users, nil
}

func (s *service) deleteUser(ctx context.Context, id string) error {
	if _, err := s.getUser(ctx, id); err != nil {
		return err
	}

	deleted, err := s.repo.deleteUser(ctx, id)
	switch {
	case err != nil:
		return fault.Internal(err)
	case !deleted:
		return userNotFound()
	}
	return nil
}

func (s *service) issueToken(ctx context.Context, userID string, ttl time.Duration) (Token, string, error) {
	if _, err := s.getUser(ctx, userID); err != nil {
		return Token{}, "", err
	}
	if ttl < 0 || ttl > maxTokenTTL {
		return Token{}, "", fault.Invalid("invalid_ttl",
			fmt.Sprintf("ttl must be between 0 and %s", maxTokenTTL))
	}

	secret, parts, err := s.mintUnusedSecret(ctx)
	if err != nil {
		return Token{}, "", err
	}

	t := Token{
		ID:        ids.New(tokenIDPrefix),
		UserID:    userID,
		Selector:  parts.selector,
		CreatedAt: s.now(),
	}
	if ttl > 0 {
		t.ExpiresAt = t.CreatedAt.Add(ttl)
	}

	if err := s.repo.insertToken(ctx, t, hashVerifier(parts.verifier)); err != nil {
		return Token{}, "", fault.Internal(err)
	}

	return t, secret, nil
}

func (s *service) mintUnusedSecret(ctx context.Context) (string, secretParts, error) {
	for range selectorAttempts {
		secret, parts := newSecret()

		taken, err := s.repo.selectorTaken(ctx, parts.selector)
		if err != nil {
			return "", secretParts{}, fault.Internal(err)
		}
		if !taken {
			return secret, parts, nil
		}
	}
	return "", secretParts{}, fault.Internal(errSelectorTaken)
}

func (s *service) listTokens(ctx context.Context, userID string) ([]Token, error) {
	if _, err := s.getUser(ctx, userID); err != nil {
		return nil, err
	}

	tokens, err := s.repo.listTokens(ctx, userID)
	if err != nil {
		return nil, fault.Internal(err)
	}
	return tokens, nil
}

func (s *service) revokeToken(ctx context.Context, id string) error {
	if !ids.HasPrefix(id, tokenIDPrefix) {
		return fault.Invalid("invalid_id", "a token id looks like "+tokenIDPrefix+"-<random>")
	}

	deleted, err := s.repo.deleteToken(ctx, id)
	switch {
	case err != nil:
		return fault.Internal(err)
	case !deleted:
		return fault.NotFound("token_not_found", "no token with that id exists")
	}
	return nil
}

func (s *service) authenticate(ctx context.Context, secret string) (authz.Identity, error) {
	parts, ok := parseSecret(secret)
	if !ok {
		return authz.Identity{}, authz.InvalidToken()
	}

	rec, err := s.repo.tokenBySelector(ctx, parts.selector)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return authz.Identity{}, authz.InvalidToken()
	case err != nil:
		return authz.Identity{}, fault.Internal(err)
	}

	if !verifierMatches(rec.verifierHash, parts.verifier) {
		return authz.Identity{}, authz.InvalidToken()
	}
	if rec.expired(s.now()) {
		return authz.Identity{}, authz.InvalidToken()
	}
	if rec.userDisabled {
		return authz.Identity{}, authz.InvalidToken()
	}

	return authz.Identity{
		UserID:  rec.UserID,
		Name:    rec.userName,
		Role:    rec.userRole,
		TokenID: rec.ID,
	}, nil
}

func (s *service) bootstrap(ctx context.Context) (string, error) {
	count, err := s.repo.countUsers(ctx)
	if err != nil {
		return "", fault.Internal(err)
	}
	if count > 0 {
		return "", nil
	}

	u, err := s.createUser(ctx, CreateUserInput{Name: bootstrapUserName, Role: authz.RoleAdmin})
	if err != nil {
		return "", err
	}

	_, secret, err := s.issueToken(ctx, u.ID, 0)
	if err != nil {
		return "", err
	}
	return secret, nil
}

func userNotFound() error {
	return fault.NotFound("user_not_found", "no user with that id exists")
}
