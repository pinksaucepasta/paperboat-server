package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
)

type DB struct {
	sql *sql.DB
}

type Tx struct {
	tx *sql.Tx
}

func Open(cfg config.Database) (*DB, error) {
	if cfg.Driver != "postgres" && cfg.Driver != "pgx" {
		return nil, fmt.Errorf("unsupported database driver %q: postgres is required for first release", cfg.Driver)
	}
	if strings.TrimSpace(cfg.DSN) == "" {
		return nil, errors.New("database dsn is required")
	}
	conn, err := sql.Open("pgx", cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	conn.SetMaxOpenConns(20)
	conn.SetMaxIdleConns(10)
	conn.SetConnMaxLifetime(30 * time.Minute)
	return &DB{sql: conn}, nil
}

func (d *DB) Close() error {
	if d == nil || d.sql == nil {
		return nil
	}
	return d.sql.Close()
}

func (d *DB) Ping(ctx context.Context) error {
	if d == nil || d.sql == nil {
		return errors.New("database is not open")
	}
	return d.sql.PingContext(ctx)
}

func (d *DB) SQL() *sql.DB {
	if d == nil {
		return nil
	}
	return d.sql
}

func (d *DB) InTx(ctx context.Context, fn func(context.Context, *Tx) error) error {
	tx, err := d.sql.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	wrapped := &Tx{tx: tx}
	if _, err := wrapped.Exec(ctx, `SET LOCAL search_path TO paperboat`); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("set transaction search path: %w", err)
	}
	if err := fn(ctx, wrapped); err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return fmt.Errorf("rollback after %v: %w", err, rollbackErr)
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (tx *Tx) Exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return tx.tx.ExecContext(ctx, query, args...)
}

func (tx *Tx) QueryRow(ctx context.Context, query string, args ...any) *sql.Row {
	return tx.tx.QueryRowContext(ctx, query, args...)
}
