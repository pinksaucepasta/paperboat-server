-- name: GetBillingEntitlement :one
SELECT s.state, p.code AS plan_code, p.name AS plan_name, s.current_period_start, s.current_period_end
FROM subscriptions s
LEFT JOIN plan_versions pv ON pv.id = s.active_plan_version_id
LEFT JOIN plans p ON p.id = pv.plan_id
WHERE s.user_id = $1 ORDER BY s.updated_at DESC, s.created_at DESC LIMIT 1;

-- name: GetBillingUsage :one
SELECT coalesce(ca.balance, 0)::text AS credits_balance,
       coalesce(sa.included_gb, 0) AS included_storage_gb,
       coalesce(sa.purchased_gb, 0) AS purchased_storage_gb,
       coalesce(sa.allocated_gb, 0) AS allocated_storage_gb,
       coalesce(sa.included_gb + sa.purchased_gb - sa.allocated_gb, 0)::integer AS available_storage_gb
FROM users u LEFT JOIN credit_accounts ca ON ca.user_id = u.id LEFT JOIN storage_accounts sa ON sa.user_id = u.id
WHERE u.id = $1;

-- name: GetFreeBillingPlan :one
SELECT pv.id, p.name, pv.included_credits::text AS included_credits, pv.included_storage_gb
FROM plans p JOIN plan_versions pv ON pv.id = p.current_version_id
WHERE p.code = 'free' AND p.active LIMIT 1;

-- name: GetBillingProductByCode :one
SELECT bp.code, bp.catalog_type, bp.catalog_ref, bp.provider_product_id, bp.provider_price_id
FROM billing_products bp
WHERE bp.code = $1 AND bp.provider = 'polar' AND bp.active
	AND (bp.catalog_type <> 'plan' OR EXISTS (SELECT 1 FROM plans p WHERE p.code = bp.catalog_ref AND p.active));

-- name: ListBillingPlanProducts :many
SELECT bp.code, p.code AS plan_code, p.name AS plan_name, pv.included_credits::text AS included_credits, pv.included_storage_gb, pv.metadata
FROM billing_products bp JOIN plans p ON p.code = bp.catalog_ref JOIN plan_versions pv ON pv.id = p.current_version_id
WHERE bp.provider = 'polar' AND bp.catalog_type = 'plan' AND bp.active AND p.active
ORDER BY p.code, bp.code;

-- name: GetBillingProductByProviderIDs :one
SELECT code, catalog_type, catalog_ref, provider_product_id, provider_price_id
FROM billing_products
WHERE provider = 'polar' AND active
  AND (sqlc.arg(provider_product_id)::text = '' OR provider_product_id = sqlc.arg(provider_product_id))
  AND provider_price_id = sqlc.arg(provider_price_id)
ORDER BY updated_at DESC LIMIT 1;

-- name: InsertPolarEvent :execrows
INSERT INTO polar_events (id, provider_event_id, event_type, processed_state, payload)
VALUES (sqlc.arg(id), sqlc.arg(provider_event_id), sqlc.arg(event_type), 'processing', sqlc.arg(payload)::jsonb) ON CONFLICT (provider_event_id) DO NOTHING;

-- name: MarkPolarEventFailed :exec
UPDATE polar_events SET processed_state = 'failed', processed_at = now() WHERE provider_event_id = $1;

-- name: MarkPolarEventProcessed :exec
UPDATE polar_events SET processed_state = 'processed', processed_at = now() WHERE provider_event_id = $1;

-- name: UpdateRefundedSubscription :exec
UPDATE subscriptions SET state = sqlc.arg(state), version = version + 1, updated_at = now()
WHERE provider = 'polar' AND provider_subscription_id = sqlc.arg(provider_subscription_id) AND user_id = sqlc.arg(user_id);

-- name: GetActivePlanVersionForWebhook :one
SELECT pv.id, pv.included_credits::text AS included_credits, pv.included_storage_gb
FROM plans p JOIN plan_versions pv ON pv.id = p.current_version_id WHERE p.code = $1 AND p.active;

-- name: UpsertPolarSubscription :exec
INSERT INTO subscriptions (id, user_id, provider, provider_subscription_id, state, active_plan_version_id, current_period_start, current_period_end)
VALUES (sqlc.arg(id), sqlc.arg(user_id), 'polar', sqlc.arg(provider_subscription_id), sqlc.arg(state), sqlc.arg(active_plan_version_id), sqlc.narg(current_period_start), sqlc.narg(current_period_end))
ON CONFLICT (provider_subscription_id) DO UPDATE SET
	user_id = EXCLUDED.user_id, state = EXCLUDED.state, active_plan_version_id = EXCLUDED.active_plan_version_id,
	current_period_start = EXCLUDED.current_period_start, current_period_end = EXCLUDED.current_period_end,
	version = subscriptions.version + 1, updated_at = now();

-- name: GetCreditBalanceForUpdate :one
SELECT balance::text FROM credit_accounts WHERE id = $1 FOR UPDATE;

-- name: NumericGreaterThanOrEqual :one
SELECT $1::numeric >= $2::numeric;

-- name: InsertCreditLedgerEntry :execrows
INSERT INTO credit_ledger_entries (id, account_id, entry_type, amount, source_type, source_id, idempotency_key, metadata)
VALUES (sqlc.arg(id), sqlc.arg(account_id), sqlc.arg(entry_type), sqlc.arg(amount)::numeric, sqlc.arg(source_type), sqlc.arg(source_id), sqlc.arg(idempotency_key), sqlc.arg(metadata)::jsonb)
ON CONFLICT (idempotency_key) DO NOTHING;

-- name: AddCreditBalance :exec
UPDATE credit_accounts SET balance = balance + sqlc.arg(amount)::numeric, version = version + 1, updated_at = now() WHERE id = sqlc.arg(id);

-- name: SubtractCreditBalance :exec
UPDATE credit_accounts SET balance = balance - sqlc.arg(amount)::numeric, version = version + 1, updated_at = now() WHERE id = sqlc.arg(id);

-- name: GetCreditLedgerEntry :one
SELECT account_id, entry_type, amount::text AS amount, source_type, source_id
FROM credit_ledger_entries WHERE idempotency_key = $1;

-- name: NumericEqual :one
SELECT $1::numeric = $2::numeric;

-- name: GetAllocatedStorageForUpdate :one
SELECT allocated_gb FROM storage_accounts WHERE id = $1 FOR UPDATE;

-- name: DecreaseAllocatedStorage :exec
UPDATE storage_accounts SET allocated_gb = allocated_gb - $2, version = version + 1, updated_at = now() WHERE id = $1;

-- name: GetIncludedAndAllocatedStorageForUpdate :one
SELECT included_gb, allocated_gb FROM storage_accounts WHERE id = $1 FOR UPDATE;

-- name: SetPurchasedStorage :exec
UPDATE storage_accounts SET purchased_gb = $2, version = version + 1, updated_at = now() WHERE id = $1;

-- name: StorageLedgerEntryExists :one
SELECT EXISTS (SELECT 1 FROM storage_ledger_entries WHERE idempotency_key = $1);

-- name: InsertStorageLedgerEntry :exec
INSERT INTO storage_ledger_entries (id, account_id, entry_type, amount_gb, source_type, source_id, idempotency_key, metadata)
VALUES (sqlc.arg(id), sqlc.arg(account_id), sqlc.arg(entry_type), sqlc.arg(amount_gb), sqlc.arg(source_type), sqlc.arg(source_id), sqlc.arg(idempotency_key), sqlc.arg(metadata)::jsonb);

-- name: InsertStorageLedgerEntryIdempotent :execrows
INSERT INTO storage_ledger_entries (id, account_id, entry_type, amount_gb, source_type, source_id, idempotency_key, metadata)
VALUES (sqlc.arg(id), sqlc.arg(account_id), sqlc.arg(entry_type), sqlc.arg(amount_gb), sqlc.arg(source_type), sqlc.arg(source_id), sqlc.arg(idempotency_key), sqlc.arg(metadata)::jsonb)
ON CONFLICT (idempotency_key) DO NOTHING;
