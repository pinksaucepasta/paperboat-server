package metering

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
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
		q := tx.Queries()
		account, err := q.GetStorageAccountForUpdate(ctx, accountID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("storage account not found")
			}
			return err
		}
		existingRow, err := q.GetStorageLedgerEntryByIdempotencyKey(ctx, idempotencyKey)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		} else {
			existing := storageLedgerEntry{accountID: existingRow.AccountID, entryType: existingRow.EntryType, amountGB: int(existingRow.AmountGb), sourceType: existingRow.SourceType, sourceID: existingRow.SourceID}
			if existing.matches(accountID, projectID, amountGB) {
				return nil
			}
			return ErrIdempotencyConflict
		}
		if int(account.AllocatedGb)+amountGB > int(account.IncludedGb+account.PurchasedGb) {
			return ErrInsufficientStorage
		}
		if err := q.IncreaseAllocatedStorage(ctx, dbsqlc.IncreaseAllocatedStorageParams{ID: accountID, AllocatedGb: int32(amountGB)}); err != nil {
			return err
		}
		if err := q.CreateStorageAllocationEntry(ctx, dbsqlc.CreateStorageAllocationEntryParams{ID: entryID, AccountID: accountID, AmountGb: int32(amountGB), SourceID: projectID, IdempotencyKey: idempotencyKey}); err != nil {
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
