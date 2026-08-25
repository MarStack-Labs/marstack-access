package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func testMigrations() []Migration {
	return []Migration{
		{Module: "target", Index: 1, SQL: `CREATE TABLE targets (id TEXT PRIMARY KEY, name TEXT NOT NULL)`},
		{Module: "target", Index: 2, SQL: `CREATE UNIQUE INDEX targets_name ON targets (name)`},
	}
}

func openStore(t *testing.T, dir string) *Store {
	t.Helper()

	st, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func countRows(t *testing.T, st *Store, query string) int {
	t.Helper()

	var n int
	if err := st.DB().QueryRowContext(context.Background(), query).Scan(&n); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return n
}

func TestMigrateIsIdempotent(t *testing.T) {
	dir := t.TempDir()

	for range 3 {
		st, err := Open(context.Background(), dir)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if err := st.Migrate(context.Background(), testMigrations()); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		st.Close()
	}

	st := openStore(t, dir)
	if applied := countRows(t, st, `SELECT COUNT(*) FROM schema_migrations`); applied != len(testMigrations()) {
		t.Fatalf("applied migrations = %d, want %d", applied, len(testMigrations()))
	}
}

func TestMigrateRecordsEachModuleSeparately(t *testing.T) {
	st := openStore(t, t.TempDir())

	migrations := append(testMigrations(), Migration{
		Module: "session",
		Index:  1,
		SQL:    `CREATE TABLE sessions (id TEXT PRIMARY KEY)`,
	})
	if err := st.Migrate(context.Background(), migrations); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	if modules := countRows(t, st, `SELECT COUNT(DISTINCT module) FROM schema_migrations`); modules != 2 {
		t.Fatalf("distinct modules = %d, want 2", modules)
	}
}

func TestModuleIndexesDoNotCollideAcrossModules(t *testing.T) {
	st := openStore(t, t.TempDir())

	migrations := []Migration{
		{Module: "target", Index: 1, SQL: `CREATE TABLE targets (id TEXT PRIMARY KEY)`},
		{Module: "session", Index: 1, SQL: `CREATE TABLE sessions (id TEXT PRIMARY KEY)`},
	}
	if err := st.Migrate(context.Background(), migrations); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	if applied := countRows(t, st, `SELECT COUNT(*) FROM schema_migrations`); applied != 2 {
		t.Fatalf("applied = %d, want 2: index 1 of one module must not shadow index 1 of another", applied)
	}
}

func TestMigrateRollsBackAFailedMigration(t *testing.T) {
	st := openStore(t, t.TempDir())

	broken := []Migration{{Module: "target", Index: 1, SQL: `CREATE TABLE ( invalid sql`}}
	if err := st.Migrate(context.Background(), broken); err == nil {
		t.Fatal("expected the migration to fail")
	}

	if recorded := countRows(t, st, `SELECT COUNT(*) FROM schema_migrations`); recorded != 0 {
		t.Fatalf("recorded = %d, want 0: a failed migration must leave no record to skip on the next run", recorded)
	}
}

func TestMigrateStopsAtTheFirstFailure(t *testing.T) {
	st := openStore(t, t.TempDir())

	migrations := []Migration{
		{Module: "target", Index: 1, SQL: `CREATE TABLE targets (id TEXT PRIMARY KEY)`},
		{Module: "target", Index: 2, SQL: `CREATE TABLE ( invalid sql`},
		{Module: "target", Index: 3, SQL: `CREATE TABLE grants (id TEXT PRIMARY KEY)`},
	}
	if err := st.Migrate(context.Background(), migrations); err == nil {
		t.Fatal("expected the migration run to fail")
	}

	if applied := countRows(t, st, `SELECT COUNT(*) FROM schema_migrations`); applied != 1 {
		t.Fatalf("applied = %d, want 1: migration 3 must not run after 2 failed", applied)
	}
}

func TestDataDirIsNotWorldReadable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")

	openStore(t, dir)

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat data dir: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o007 != 0 {
		t.Fatalf("data dir mode = %#o, want no permissions for other: it holds session metadata", perm)
	}
}

func TestForeignKeysAreEnforced(t *testing.T) {
	st := openStore(t, t.TempDir())
	ctx := context.Background()

	setup := []Migration{
		{Module: "target", Index: 1, SQL: `CREATE TABLE targets (id TEXT PRIMARY KEY)`},
		{Module: "session", Index: 1, SQL: `CREATE TABLE sessions (
			id        TEXT PRIMARY KEY,
			target_id TEXT NOT NULL REFERENCES targets (id)
		)`},
	}
	if err := st.Migrate(ctx, setup); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	_, err := st.DB().ExecContext(ctx,
		`INSERT INTO sessions (id, target_id) VALUES ('ses-1', 'tgt-missing')`)
	if err == nil {
		t.Fatal("a session referencing a missing target was accepted: foreign_keys is off")
	}
}

func TestPingReportsAClosedStore(t *testing.T) {
	st, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	st.Close()

	if err := st.Ping(context.Background()); err == nil {
		t.Fatal("Ping succeeded on a closed store, so /healthz would report a lie")
	}
}
