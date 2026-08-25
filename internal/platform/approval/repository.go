package approval

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type repository struct {
	db *sql.DB
}

const selectColumns = `id, requester_id, target_id, principal, reason, state,
	grant_ttl_seconds, created_at, request_expires_at, decided_by, decided_at, grant_expires_at`

func (r *repository) insert(ctx context.Context, req Request) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO access_requests
		 (id, requester_id, target_id, principal, reason, state,
		  grant_ttl_seconds, created_at, request_expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		req.ID, req.RequesterID, req.TargetID, req.Principal, req.Reason, req.State,
		int64(req.GrantTTL.Seconds()),
		req.CreatedAt.UTC().Format(time.RFC3339),
		req.RequestExpiresAt.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("insert request: %w", err)
	}
	return nil
}

func (r *repository) get(ctx context.Context, id string) (Request, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+selectColumns+` FROM access_requests WHERE id = ?`, id)
	return scanRequest(row)
}

func (r *repository) list(ctx context.Context, requesterID string) ([]Request, error) {
	query := `SELECT ` + selectColumns + ` FROM access_requests`
	args := []any{}
	if requesterID != "" {
		query += ` WHERE requester_id = ?`
		args = append(args, requesterID)
	}
	query += ` ORDER BY created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list requests: %w", err)
	}
	defer rows.Close()

	requests := []Request{}
	for rows.Next() {
		req, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		requests = append(requests, req)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate requests: %w", err)
	}
	return requests, nil
}

func (r *repository) decide(ctx context.Context, id, state, decidedBy string, decidedAt, grantExpiresAt time.Time) (bool, error) {
	var expires any
	if !grantExpiresAt.IsZero() {
		expires = grantExpiresAt.UTC().Format(time.RFC3339)
	}

	res, err := r.db.ExecContext(ctx,
		`UPDATE access_requests
		 SET state = ?, decided_by = ?, decided_at = ?, grant_expires_at = ?
		 WHERE id = ? AND state = ?`,
		state, decidedBy, decidedAt.UTC().Format(time.RFC3339), expires,
		id, StatePending,
	)
	if err != nil {
		return false, fmt.Errorf("decide request: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("rows affected: %w", err)
	}
	return affected > 0, nil
}

func (r *repository) activeGrant(ctx context.Context, q GrantQuery, now time.Time) (Request, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+selectColumns+`
		 FROM access_requests
		 WHERE requester_id = ? AND target_id = ? AND principal = ?
		   AND state = ? AND grant_expires_at > ?
		 ORDER BY grant_expires_at DESC
		 LIMIT 1`,
		q.UserID, q.TargetID, q.Principal, StateApproved, now.UTC().Format(time.RFC3339))
	return scanRequest(row)
}

type scanner interface {
	Scan(dest ...any) error
}

func scanRequest(row scanner) (Request, error) {
	var (
		req              Request
		ttlSeconds       int64
		createdAt        string
		requestExpiresAt string
		decidedBy        sql.NullString
		decidedAt        sql.NullString
		grantExpiresAt   sql.NullString
	)

	if err := row.Scan(&req.ID, &req.RequesterID, &req.TargetID, &req.Principal, &req.Reason,
		&req.State, &ttlSeconds, &createdAt, &requestExpiresAt,
		&decidedBy, &decidedAt, &grantExpiresAt); err != nil {
		return Request{}, err
	}

	req.GrantTTL = time.Duration(ttlSeconds) * time.Second

	var err error
	if req.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
		return Request{}, fmt.Errorf("parse created_at: %w", err)
	}
	if req.RequestExpiresAt, err = time.Parse(time.RFC3339, requestExpiresAt); err != nil {
		return Request{}, fmt.Errorf("parse request_expires_at: %w", err)
	}
	if decidedBy.Valid {
		req.DecidedBy = decidedBy.String
	}
	if decidedAt.Valid {
		if req.DecidedAt, err = time.Parse(time.RFC3339, decidedAt.String); err != nil {
			return Request{}, fmt.Errorf("parse decided_at: %w", err)
		}
	}
	if grantExpiresAt.Valid {
		if req.GrantExpiresAt, err = time.Parse(time.RFC3339, grantExpiresAt.String); err != nil {
			return Request{}, fmt.Errorf("parse grant_expires_at: %w", err)
		}
	}

	return req, nil
}
