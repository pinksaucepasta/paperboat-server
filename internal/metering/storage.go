package metering

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

var ErrInsufficientStorage = errors.New("insufficient storage available")
var ErrIdempotencyConflict = errors.New("idempotency key conflicts with existing storage ledger entry")

type StorageAllocator interface {
	Allocate(ctx context.Context, accountID, projectID, entryID, idempotencyKey string, amountGB int) error
}

type StorageRepository struct {
	db *db.DB
}

func NewStorageRepository(store *db.DB) *StorageRepository {
	return &StorageRepository{db: store}
}

func (r *StorageRepository) Allocate(ctx context.Context, accountID, projectID, entryID, idempotencyKey string, amountGB int) error {
	if amountGB <= 0 {
		return fmt.Errorf("amount_gb must be positive")
	}
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		err = r.allocateOnce(ctx, accountID, projectID, entryID, idempotencyKey, amountGB)
		if !isSerializationFailure(err) {
			return err
		}
	}
	return err
}

func (r *StorageRepository) allocateOnce(ctx context.Context, accountID, projectID, entryID, idempotencyKey string, amountGB int) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var included, purchased, allocated int
		if err := tx.QueryRow(ctx, `
SELECT included_gb, purchased_gb, allocated_gb
FROM storage_accounts
WHERE id = $1
FOR UPDATE`, accountID).Scan(&included, &purchased, &allocated); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("storage account not found")
			}
			return err
		}
		var existing storageLedgerEntry
		if err := tx.QueryRow(ctx, `
SELECT account_id, entry_type, amount_gb, source_type, source_id
FROM storage_ledger_entries
WHERE idempotency_key = $1`, idempotencyKey).Scan(&existing.accountID, &existing.entryType, &existing.amountGB, &existing.sourceType, &existing.sourceID); err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		} else {
			if existing.matches(accountID, projectID, amountGB) {
				return nil
			}
			return ErrIdempotencyConflict
		}
		if allocated+amountGB > included+purchased {
			return ErrInsufficientStorage
		}
		if _, err := tx.Exec(ctx, `
UPDATE storage_accounts
SET allocated_gb = allocated_gb + $2, version = version + 1, updated_at = now()
WHERE id = $1`, accountID, amountGB); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO storage_ledger_entries (id, account_id, entry_type, amount_gb, source_type, source_id, idempotency_key)
VALUES ($1, $2, 'allocation', $3, 'project', $4, $5)
`, entryID, accountID, amountGB, projectID, idempotencyKey); err != nil {
			return err
		}
		return nil
	})
}

type storageLedgerEntry struct {
	accountID  string
	entryType  string
	amountGB   int
	sourceType string
	sourceID   string
}

func (e storageLedgerEntry) matches(accountID, projectID string, amountGB int) bool {
	return e.accountID == accountID &&
		e.entryType == "allocation" &&
		e.amountGB == amountGB &&
		e.sourceType == "project" &&
		e.sourceID == projectID
}

func isSerializationFailure(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40001"
}
