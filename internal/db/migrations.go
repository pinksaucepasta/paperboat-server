package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"hash/fnv"

	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

const migrationsDir = "migrations"

func Migrate(ctx context.Context, d *DB) error {
	if err := d.Ping(ctx); err != nil {
		return err
	}
	conn, err := d.sql.Conn(ctx)
	if err != nil {
		return fmt.Errorf("open migration connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, migrationLockKey()); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, migrationLockKey())
	if _, err := conn.ExecContext(ctx, `CREATE SCHEMA IF NOT EXISTS paperboat`); err != nil {
		return fmt.Errorf("ensure paperboat schema: %w", err)
	}

	goose.SetBaseFS(migrationsFS)
	goose.SetTableName("paperboat.goose_db_version")
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("set migration dialect: %w", err)
	}
	if err := adoptLegacyMigrationHistory(ctx, d.sql); err != nil {
		return err
	}
	if err := goose.UpContext(ctx, d.sql, migrationsDir); err != nil {
		return fmt.Errorf("run migrations: %w", err)
	}
	return nil
}

// adoptLegacyMigrationHistory prevents Goose from replaying migrations already
// applied by the original in-process runner. Fresh databases have neither table
// and proceed through the normal Goose migration path.
func adoptLegacyMigrationHistory(ctx context.Context, database *sql.DB) error {
	var gooseTableExists bool
	if err := database.QueryRowContext(ctx, `SELECT to_regclass('paperboat.goose_db_version') IS NOT NULL`).Scan(&gooseTableExists); err != nil {
		return fmt.Errorf("check goose migration history: %w", err)
	}
	if gooseTableExists {
		return nil
	}
	var legacyTableExists bool
	if err := database.QueryRowContext(ctx, `SELECT to_regclass('paperboat.schema_migrations') IS NOT NULL`).Scan(&legacyTableExists); err != nil {
		return fmt.Errorf("check legacy migration history: %w", err)
	}
	if !legacyTableExists {
		return nil
	}
	if _, err := goose.EnsureDBVersionContext(ctx, database); err != nil {
		return fmt.Errorf("initialize goose migration history: %w", err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO paperboat.goose_db_version (version_id, is_applied)
SELECT version, true
FROM paperboat.schema_migrations
WHERE version > 0
ORDER BY version`); err != nil {
		return fmt.Errorf("adopt legacy migration history: %w", err)
	}
	return nil
}

func migrationLockKey() int64 {
	hash := fnv.New64a()
	_, _ = hash.Write([]byte("paperboat-server:migrations"))
	return int64(hash.Sum64())
}
