-- name: GetStorageAccountForUpdate :one
SELECT included_gb, purchased_gb, allocated_gb
FROM storage_accounts
WHERE id = $1
FOR UPDATE;

-- name: GetStorageLedgerEntryByIdempotencyKey :one
SELECT account_id, entry_type, amount_gb, source_type, source_id
FROM storage_ledger_entries
WHERE idempotency_key = $1;

-- name: IncreaseAllocatedStorage :exec
UPDATE storage_accounts
SET allocated_gb = allocated_gb + $2, version = version + 1, updated_at = now()
WHERE id = $1;

-- name: CreateStorageAllocationEntry :exec
INSERT INTO storage_ledger_entries (id, account_id, entry_type, amount_gb, source_type, source_id, idempotency_key)
VALUES ($1, $2, 'allocation', $3, 'project', $4, $5);
