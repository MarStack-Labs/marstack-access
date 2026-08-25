package policy

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type repository struct {
	db *sql.DB
}

func (r *repository) insert(ctx context.Context, p Policy) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback()

	var taken int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM policies WHERE name = ?`, p.Name,
	).Scan(&taken); err != nil {
		return fmt.Errorf("check name: %w", err)
	}
	if taken > 0 {
		return errNameTaken
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO policies (id, name, subject_kind, subject_id, target_id, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		p.ID, p.Name, p.SubjectKind, p.SubjectID, p.TargetID,
		p.CreatedAt.UTC().Format(time.RFC3339),
	); err != nil {
		return fmt.Errorf("insert policy: %w", err)
	}

	for _, principal := range p.Principals {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO policy_principals (policy_id, principal) VALUES (?, ?)`,
			p.ID, principal,
		); err != nil {
			return fmt.Errorf("insert principal: %w", err)
		}
	}

	return tx.Commit()
}

func (r *repository) get(ctx context.Context, id string) (Policy, error) {
	var (
		p         Policy
		createdAt string
	)

	err := r.db.QueryRowContext(ctx,
		`SELECT id, name, subject_kind, subject_id, target_id, created_at
		 FROM policies WHERE id = ?`, id,
	).Scan(&p.ID, &p.Name, &p.SubjectKind, &p.SubjectID, &p.TargetID, &createdAt)
	if err != nil {
		return Policy{}, err
	}

	p.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return Policy{}, fmt.Errorf("parse created_at: %w", err)
	}

	p.Principals, err = r.principalsOf(ctx, id)
	if err != nil {
		return Policy{}, err
	}
	return p, nil
}

func (r *repository) list(ctx context.Context) ([]Policy, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, name, subject_kind, subject_id, target_id, created_at
		 FROM policies ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list policies: %w", err)
	}
	defer rows.Close()

	policies := []Policy{}
	for rows.Next() {
		var (
			p         Policy
			createdAt string
		)
		if err := rows.Scan(&p.ID, &p.Name, &p.SubjectKind, &p.SubjectID, &p.TargetID, &createdAt); err != nil {
			return nil, fmt.Errorf("scan policy: %w", err)
		}
		p.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
		if err != nil {
			return nil, fmt.Errorf("parse created_at: %w", err)
		}
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policies: %w", err)
	}

	for i := range policies {
		policies[i].Principals, err = r.principalsOf(ctx, policies[i].ID)
		if err != nil {
			return nil, err
		}
	}
	return policies, nil
}

func (r *repository) principalsOf(ctx context.Context, id string) ([]string, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT principal FROM policy_principals WHERE policy_id = ? ORDER BY principal`, id)
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
	res, err := r.db.ExecContext(ctx, `DELETE FROM policies WHERE id = ?`, id)
	if err != nil {
		return false, fmt.Errorf("delete policy: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("rows affected: %w", err)
	}
	return affected > 0, nil
}

func (r *repository) matching(ctx context.Context, req Request) (string, error) {
	var id string

	err := r.db.QueryRowContext(ctx,
		`SELECT p.id
		 FROM policies p
		 JOIN policy_principals pp ON pp.policy_id = p.id
		 WHERE p.target_id = ?
		   AND pp.principal = ?
		   AND ((p.subject_kind = ? AND p.subject_id = ?)
		     OR (p.subject_kind = ? AND p.subject_id = ?))
		 ORDER BY p.subject_kind, p.name
		 LIMIT 1`,
		req.TargetID, req.Principal,
		SubjectUser, req.UserID,
		SubjectRole, req.Role,
	).Scan(&id)
	if err != nil {
		return "", err
	}
	return id, nil
}
