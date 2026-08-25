package store

import (
	"context"
	"fmt"
	"time"
)

type Migration struct {
	Module string
	Index  int
	SQL    string
}

const migrationTable = `CREATE TABLE IF NOT EXISTS schema_migrations (
	module     TEXT    NOT NULL,
	idx        INTEGER NOT NULL,
	applied_at TEXT    NOT NULL,
	PRIMARY KEY (module, idx)
)`

func (s *Store) Migrate(ctx context.Context, migrations []Migration) error {
	if _, err := s.db.ExecContext(ctx, migrationTable); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	for _, m := range migrations {
		applied, err := s.migrationApplied(ctx, m)
		if err != nil {
			return err
		}
		if applied {
			continue
		}
		if err := s.applyMigration(ctx, m); err != nil {
			return err
		}
	}

	return nil
}

func (s *Store) migrationApplied(ctx context.Context, m Migration) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM schema_migrations WHERE module = ? AND idx = ?`,
		m.Module, m.Index,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("check migration %s/%d: %w", m.Module, m.Index, err)
	}
	return count > 0, nil
}

func (s *Store) applyMigration(ctx context.Context, m Migration) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration %s/%d: %w", m.Module, m.Index, err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
		return fmt.Errorf("apply migration %s/%d: %w", m.Module, m.Index, err)
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (module, idx, applied_at) VALUES (?, ?, ?)`,
		m.Module, m.Index, time.Now().UTC().Format(time.RFC3339),
	); err != nil {
		return fmt.Errorf("record migration %s/%d: %w", m.Module, m.Index, err)
	}

	return tx.Commit()
}
