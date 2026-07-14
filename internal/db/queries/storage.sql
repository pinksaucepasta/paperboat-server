-- name: GetStorageAccountForUpdate :one
SELECT least(sa.included_gb, coalesce(limits.pending_included_gb, sa.included_gb))::integer AS included_gb,
       least(sa.purchased_gb, coalesce(limits.pending_purchased_gb, sa.purchased_gb))::integer AS purchased_gb,
       sa.allocated_gb
FROM storage_accounts sa
LEFT JOIN LATERAL (
  SELECT pending_pv.included_storage_gb AS pending_included_gb,
         CASE WHEN s.pending_storage_units IS NULL THEN NULL ELSE
           greatest(0, s.pending_storage_units - coalesce((active_pv.metadata->'billing'->>'storage_seat_offset')::integer,0)) *
           coalesce((active_pv.metadata->'billing'->>'storage_unit_gb')::integer,0)
         END AS pending_purchased_gb
  FROM subscriptions s
  LEFT JOIN plan_versions active_pv ON active_pv.id=s.active_plan_version_id
  LEFT JOIN plan_versions pending_pv ON pending_pv.id=s.pending_plan_version_id
  WHERE s.user_id=sa.user_id AND s.provider='polar' AND s.state IN ('active','trialing')
  ORDER BY s.updated_at DESC LIMIT 1
) limits ON true
WHERE sa.id = $1
FOR UPDATE OF sa;

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
