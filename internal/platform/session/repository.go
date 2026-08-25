package session

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type repository struct {
	db *sql.DB
}

const columns = `id, user_id, user_name, target_id, target_name, principal,
	credential_id, remote_addr, recording, started_at, ended_at,
	exit_code, reason, recorded_bytes`

func (r *repository) insert(ctx context.Context, s Session) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO sessions
		 (id, user_id, user_name, target_id, target_name, principal,
		  credential_id, remote_addr, recording, started_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.ID, s.UserID, s.UserName, s.TargetID, s.TargetName, s.Principal,
		s.CredentialID, s.RemoteAddr, s.Recording,
		s.StartedAt.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("insert session: %w", err)
	}
	return nil
}

func (r *repository) finish(ctx context.Context, id string, endedAt time.Time, in CloseInput) (bool, error) {
	res, err := r.db.ExecContext(ctx,
		`UPDATE sessions
		 SET ended_at = ?, exit_code = ?, reason = ?, recorded_bytes = ?
		 WHERE id = ? AND ended_at IS NULL`,
		endedAt.UTC().Format(time.RFC3339), in.ExitCode, in.Reason, in.RecordedBytes, id,
	)
	if err != nil {
		return false, fmt.Errorf("finish session: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("rows affected: %w", err)
	}
	return affected > 0, nil
}

func (r *repository) closeDangling(ctx context.Context, endedAt time.Time, reason string) (int64, error) {
	res, err := r.db.ExecContext(ctx,
		`UPDATE sessions SET ended_at = ?, exit_code = ?, reason = ?
		 WHERE ended_at IS NULL`,
		endedAt.UTC().Format(time.RFC3339), -1, reason,
	)
	if err != nil {
		return 0, fmt.Errorf("close dangling sessions: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return affected, nil
}

func (r *repository) get(ctx context.Context, id string) (Session, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+columns+` FROM sessions WHERE id = ?`, id)
	return scanSession(row)
}

func (r *repository) list(ctx context.Context, userID string) ([]Session, error) {
	query := `SELECT ` + columns + ` FROM sessions`
	args := []any{}
	if userID != "" {
		query += ` WHERE user_id = ?`
		args = append(args, userID)
	}
	query += ` ORDER BY started_at DESC`

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()

	sessions := []Session{}
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sessions: %w", err)
	}
	return sessions, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanSession(row scanner) (Session, error) {
	var (
		s             Session
		startedAt     string
		endedAt       sql.NullString
		exitCode      sql.NullInt64
		reason        sql.NullString
		recordedBytes sql.NullInt64
	)

	if err := row.Scan(&s.ID, &s.UserID, &s.UserName, &s.TargetID, &s.TargetName, &s.Principal,
		&s.CredentialID, &s.RemoteAddr, &s.Recording, &startedAt, &endedAt,
		&exitCode, &reason, &recordedBytes); err != nil {
		return Session{}, err
	}

	parsed, err := time.Parse(time.RFC3339, startedAt)
	if err != nil {
		return Session{}, fmt.Errorf("parse started_at: %w", err)
	}
	s.StartedAt = parsed

	if endedAt.Valid {
		s.EndedAt, err = time.Parse(time.RFC3339, endedAt.String)
		if err != nil {
			return Session{}, fmt.Errorf("parse ended_at: %w", err)
		}
	}
	if exitCode.Valid {
		s.ExitCode = int(exitCode.Int64)
	}
	s.Reason = reason.String
	s.RecordedBytes = recordedBytes.Int64

	return s, nil
}
