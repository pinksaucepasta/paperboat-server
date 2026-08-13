package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

type DB struct {
	pool *pgxpool.Pool
	sql  *sql.DB
	q    *dbsqlc.Queries

	serializable  transactionCounters
	readCommitted transactionCounters
}

type transactionCounters struct {
	calls     atomic.Uint64
	attempts  atomic.Uint64
	retries   atomic.Uint64
	exhausted atomic.Uint64
}

type TransactionStats struct {
	Calls     uint64 `json:"calls"`
	Attempts  uint64 `json:"attempts"`
	Retries   uint64 `json:"retries"`
	Exhausted uint64 `json:"exhausted"`
}

type TransactionSnapshot struct {
	Serializable  TransactionStats `json:"serializable"`
	ReadCommitted TransactionStats `json:"read_committed"`
}

type Tx struct {
	tx pgx.Tx
	q  *dbsqlc.Queries
}

func Open(cfg config.Database) (*DB, error) {
	if cfg.Driver != "postgres" && cfg.Driver != "pgx" {
		return nil, fmt.Errorf("unsupported database driver %q: postgres is required for first release", cfg.Driver)
	}
	if strings.TrimSpace(cfg.DSN) == "" {
		return nil, errors.New("database dsn is required")
	}
	poolConfig, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("parse postgres dsn: %w", err)
	}
	poolConfig.ConnConfig.RuntimeParams["search_path"] = "paperboat"
	poolConfig.MaxConns = 20
	poolConfig.MaxConnLifetime = 30 * time.Minute
	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	return &DB{pool: pool, sql: stdlib.OpenDBFromPool(pool), q: dbsqlc.New(pool)}, nil
}

func (d *DB) Close() error {
	if d == nil || d.sql == nil {
		return nil
	}
	sqlErr := d.sql.Close()
	d.pool.Close()
	return sqlErr
}

func (d *DB) Ping(ctx context.Context) error {
	if d == nil || d.sql == nil {
		return errors.New("database is not open")
	}
	return d.pool.Ping(ctx)
}

func (d *DB) SQL() *sql.DB {
	if d == nil {
		return nil
	}
	return d.sql
}

func (d *DB) Queries() *dbsqlc.Queries {
	if d == nil {
		return nil
	}
	return d.q
}

func (d *DB) Pool() *pgxpool.Pool {
	if d == nil {
		return nil
	}
	return d.pool
}

func (d *DB) TransactionStats() TransactionSnapshot {
	if d == nil {
		return TransactionSnapshot{}
	}
	return TransactionSnapshot{
		Serializable:  d.serializable.snapshot(),
		ReadCommitted: d.readCommitted.snapshot(),
	}
}

// InTx runs fn inside a SERIALIZABLE transaction. Because serializable
// isolation can abort concurrent transactions with a serialization failure
// (40001) or deadlock (40P01), fn may be retried from a clean transaction. All
// InTx callers are idempotent (idempotency keys / ON CONFLICT), so replaying an
// aborted attempt is safe.
func (d *DB) InTx(ctx context.Context, fn func(context.Context, *Tx) error) error {
	const maxAttempts = 10
	d.serializable.calls.Add(1)
	for attempt := 1; ; attempt++ {
		d.serializable.attempts.Add(1)
		err := d.runInTx(ctx, pgx.Serializable, fn)
		if err == nil || attempt >= maxAttempts || !isSerializationFailure(err) {
			if attempt >= maxAttempts && isSerializationFailure(err) {
				d.serializable.exhausted.Add(1)
			}
			return err
		}
		// Exponential jitter prevents synchronized workers from repeatedly
		// colliding on the same serializable rows. The delay remains bounded.
		backoff := 5 * time.Millisecond << min(attempt-1, 5)
		if backoff > 200*time.Millisecond {
			backoff = 200 * time.Millisecond
		}
		half := backoff / 2
		jitter := time.Duration(time.Now().UnixNano() % int64(half+1))
		timer := time.NewTimer(half + jitter)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
			d.serializable.retries.Add(1)
		}
	}
}

// InReadCommittedTx is for bounded work-queue claims that use FOR UPDATE SKIP
// LOCKED and explicit row versions. Serializable predicate locking conflicts
// with concurrent skip-locked claimers even when their committed rows are
// disjoint; read committed preserves the row-lock contract for that pattern.
func (d *DB) InReadCommittedTx(ctx context.Context, fn func(context.Context, *Tx) error) error {
	const maxAttempts = 5
	d.readCommitted.calls.Add(1)
	for attempt := 1; ; attempt++ {
		d.readCommitted.attempts.Add(1)
		err := d.runInTx(ctx, pgx.ReadCommitted, fn)
		if err == nil || attempt >= maxAttempts || !isSerializationFailure(err) {
			if attempt >= maxAttempts && isSerializationFailure(err) {
				d.readCommitted.exhausted.Add(1)
			}
			return err
		}
		timer := time.NewTimer(time.Duration(attempt) * 5 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
			d.readCommitted.retries.Add(1)
		}
	}
}

func (c *transactionCounters) snapshot() TransactionStats {
	return TransactionStats{
		Calls:     c.calls.Load(),
		Attempts:  c.attempts.Load(),
		Retries:   c.retries.Load(),
		Exhausted: c.exhausted.Load(),
	}
}

// isSerializationFailure reports whether err is a Postgres serialization
// failure (40001) or deadlock (40P01) — both are safe to retry.
func isSerializationFailure(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "40001" || pgErr.Code == "40P01"
	}
	return false
}

func (d *DB) runInTx(ctx context.Context, isolation pgx.TxIsoLevel, fn func(context.Context, *Tx) error) error {
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: isolation})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	wrapped := &Tx{tx: tx, q: dbsqlc.New(tx)}
	if _, err := wrapped.Exec(ctx, `SET LOCAL search_path TO paperboat`); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("set transaction search path: %w", err)
	}
	if err := fn(ctx, wrapped); err != nil {
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
			return fmt.Errorf("rollback after %v: %w", err, rollbackErr)
		}
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (tx *Tx) Queries() *dbsqlc.Queries {
	if tx == nil {
		return nil
	}
	return tx.q
}

func (tx *Tx) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	return tx.tx.Exec(ctx, query, args...)
}

func (tx *Tx) QueryRow(ctx context.Context, query string, args ...any) pgx.Row {
	return tx.tx.QueryRow(ctx, query, args...)
}

func (tx *Tx) Query(ctx context.Context, query string, args ...any) (pgx.Rows, error) {
	return tx.tx.Query(ctx, query, args...)
}
