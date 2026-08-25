package target

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type repository struct {
	db *sql.DB
}

func (r *repository) insert(ctx context.Context, t Target) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback()

	var taken int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM targets WHERE name = ?`, t.Name,
	).Scan(&taken); err != nil {
		return fmt.Errorf("check name: %w", err)
	}
	if taken > 0 {
		return errNameTaken
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO targets (id, name, address, port, created_at) VALUES (?, ?, ?, ?, ?)`,
		t.ID, t.Name, t.Address, t.Port, t.CreatedAt.UTC().Format(time.RFC3339),
	); err != nil {
		return fmt.Errorf("insert target: %w", err)
	}

	for _, principal := range t.Principals {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO target_principals (target_id, principal) VALUES (?, ?)`,
			t.ID, principal,
		); err != nil {
			return fmt.Errorf("insert principal: %w", err)
		}
	}

	return tx.Commit()
}

func (r *repository) get(ctx context.Context, id string) (Target, error) {
	var (
		t         Target
		createdAt string
	)

	err := r.db.QueryRowContext(ctx,
		`SELECT id, name, address, port, created_at FROM targets WHERE id = ?`, id,
	).Scan(&t.ID, &t.Name, &t.Address, &t.Port, &createdAt)
	if err != nil {
		return Target{}, err
	}

	t.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return Target{}, fmt.Errorf("parse created_at: %w", err)
	}

	t.Principals, err = r.principalsOf(ctx, id)
	if err != nil {
		return Target{}, err
	}
	return t, nil
}

func (r *repository) list(ctx context.Context) ([]Target, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, name, address, port, created_at FROM targets ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list targets: %w", err)
	}
	defer rows.Close()

	targets := []Target{}
	for rows.Next() {
		var (
			t         Target
			createdAt string
		)
		if err := rows.Scan(&t.ID, &t.Name, &t.Address, &t.Port, &createdAt); err != nil {
			return nil, fmt.Errorf("scan target: %w", err)
		}
		t.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
		if err != nil {
			return nil, fmt.Errorf("parse created_at: %w", err)
		}
		targets = append(targets, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate targets: %w", err)
	}

	for i := range targets {
		targets[i].Principals, err = r.principalsOf(ctx, targets[i].ID)
		if err != nil {
			return nil, err
		}
	}
	return targets, nil
}

func (r *repository) principalsOf(ctx context.Context, id string) ([]string, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT principal FROM target_principals WHERE target_id = ? ORDER BY principal`, id)
	if err != nil {
		return nil, fmt.Errorf("list principals: %w", err)
	}
	defer rows.Close()

	principals := []string{}
	for rows.Next() {
		var principal string
		if err := rows.Scan(&principal); err != nil {
			return nil, fmt.Errorf("scan principal: %w", err)
		}
		principals = append(principals, principal)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate principals: %w", err)
	}
	return principals, nil
}

func (r *repository) delete(ctx context.Context, id string) (bool, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM targets WHERE id = ?`, id)
	if err != nil {
		return false, fmt.Errorf("delete target: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("rows affected: %w", err)
	}
	return affected > 0, nil
}
