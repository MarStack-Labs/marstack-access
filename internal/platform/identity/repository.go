package identity

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type repository struct {
	db *sql.DB
}

type tokenRecord struct {
	Token
	verifierHash []byte
	userName     string
	userRole     string
	userDisabled bool
}

func (r *repository) insertUser(ctx context.Context, u User) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback()

	var taken int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE name = ?`, u.Name,
	).Scan(&taken); err != nil {
		return fmt.Errorf("check name: %w", err)
	}
	if taken > 0 {
		return errNameTaken
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO users (id, name, role, disabled, created_at) VALUES (?, ?, ?, ?, ?)`,
		u.ID, u.Name, u.Role, boolToInt(u.Disabled), u.CreatedAt.UTC().Format(time.RFC3339),
	); err != nil {
		return fmt.Errorf("insert user: %w", err)
	}

	return tx.Commit()
}

func (r *repository) countUsers(ctx context.Context) (int, error) {
	var n int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return n, nil
}

func (r *repository) getUser(ctx context.Context, id string) (User, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, name, role, disabled, created_at FROM users WHERE id = ?`, id)
	return scanUser(row)
}

func (r *repository) listUsers(ctx context.Context) ([]User, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, name, role, disabled, created_at FROM users ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	users := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate users: %w", err)
	}
	return users, nil
}

func (r *repository) deleteUser(ctx context.Context, id string) (bool, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return false, fmt.Errorf("delete user: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("rows affected: %w", err)
	}
	return affected > 0, nil
}

func (r *repository) insertToken(ctx context.Context, t Token, verifierHash []byte) error {
	var expiresAt any
	if !t.ExpiresAt.IsZero() {
		expiresAt = t.ExpiresAt.UTC().Format(time.RFC3339)
	}

	_, err := r.db.ExecContext(ctx,
		`INSERT INTO tokens (id, user_id, selector, verifier_hash, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		t.ID, t.UserID, t.Selector, verifierHash,
		t.CreatedAt.UTC().Format(time.RFC3339), expiresAt,
	)
	if err != nil {
		return fmt.Errorf("insert token: %w", err)
	}
	return nil
}

func (r *repository) selectorTaken(ctx context.Context, selector string) (bool, error) {
	var n int
	if err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM tokens WHERE selector = ?`, selector,
	).Scan(&n); err != nil {
		return false, fmt.Errorf("check selector: %w", err)
	}
	return n > 0, nil
}

func (r *repository) tokenBySelector(ctx context.Context, selector string) (tokenRecord, error) {
	var (
		rec       tokenRecord
		createdAt string
		expiresAt sql.NullString
		disabled  int
	)

	err := r.db.QueryRowContext(ctx,
		`SELECT t.id, t.user_id, t.selector, t.verifier_hash, t.created_at, t.expires_at,
		        u.name, u.role, u.disabled
		 FROM tokens t JOIN users u ON u.id = t.user_id
		 WHERE t.selector = ?`, selector,
	).Scan(&rec.ID, &rec.UserID, &rec.Selector, &rec.verifierHash, &createdAt, &expiresAt,
		&rec.userName, &rec.userRole, &disabled)
	if err != nil {
		return tokenRecord{}, err
	}

	rec.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return tokenRecord{}, fmt.Errorf("parse created_at: %w", err)
	}
	if expiresAt.Valid {
		rec.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt.String)
		if err != nil {
			return tokenRecord{}, fmt.Errorf("parse expires_at: %w", err)
		}
	}
	rec.userDisabled = disabled != 0

	return rec, nil
}

func (r *repository) listTokens(ctx context.Context, userID string) ([]Token, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, user_id, selector, created_at, expires_at
		 FROM tokens WHERE user_id = ? ORDER BY created_at`, userID)
	if err != nil {
		return nil, fmt.Errorf("list tokens: %w", err)
	}
	defer rows.Close()

	tokens := []Token{}
	for rows.Next() {
		var (
			t         Token
			createdAt string
			expiresAt sql.NullString
		)
		if err := rows.Scan(&t.ID, &t.UserID, &t.Selector, &createdAt, &expiresAt); err != nil {
			return nil, fmt.Errorf("scan token: %w", err)
		}
		t.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
		if err != nil {
			return nil, fmt.Errorf("parse created_at: %w", err)
		}
		if expiresAt.Valid {
			t.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt.String)
			if err != nil {
				return nil, fmt.Errorf("parse expires_at: %w", err)
			}
		}
		tokens = append(tokens, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tokens: %w", err)
	}
	return tokens, nil
}

func (r *repository) deleteToken(ctx context.Context, id string) (bool, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM tokens WHERE id = ?`, id)
	if err != nil {
		return false, fmt.Errorf("delete token: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("rows affected: %w", err)
	}
	return affected > 0, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanUser(row scanner) (User, error) {
	var (
		u         User
		disabled  int
		createdAt string
	)

	if err := row.Scan(&u.ID, &u.Name, &u.Role, &disabled, &createdAt); err != nil {
		return User{}, err
	}

	parsed, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return User{}, fmt.Errorf("parse created_at: %w", err)
	}

	u.Disabled = disabled != 0
	u.CreatedAt = parsed
	return u, nil
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
