-- name: GetBillingEntitlement :one
SELECT s.state, p.code AS plan_code, p.name AS plan_name, s.current_period_start, s.current_period_end
FROM subscriptions s
LEFT JOIN plan_versions pv ON pv.id = s.active_plan_version_id
LEFT JOIN plans p ON p.id = pv.plan_id
WHERE s.user_id = $1 ORDER BY s.updated_at DESC, s.created_at DESC LIMIT 1;

-- name: GetActivePolarSubscriptionForUser :one
SELECT s.provider_subscription_id, p.code AS plan_code,
       coalesce((pv.metadata->'billing'->>'rank')::integer, 0)::integer AS plan_rank,
       coalesce((pv.metadata->'billing'->>'storage_unit_gb')::integer, 0)::integer AS storage_unit_gb,
       coalesce((pv.metadata->'billing'->>'storage_seat_offset')::integer, 0)::integer AS storage_seat_offset,
       s.storage_units, s.pending_storage_units
FROM subscriptions s
JOIN plan_versions pv ON pv.id = s.active_plan_version_id
JOIN plans p ON p.id = pv.plan_id
WHERE s.user_id = $1
  AND s.provider = 'polar'
  AND s.state IN ('active', 'trialing')
  AND (s.current_period_end IS NULL OR s.current_period_end > now())
ORDER BY s.updated_at DESC, s.created_at DESC
LIMIT 1;

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
SELECT bp.code, bp.catalog_type, bp.catalog_ref, bp.provider_product_id, bp.provider_price_id,
       coalesce((pv.metadata->'billing'->>'rank')::integer, 0)::integer AS plan_rank,
       (coalesce((pv.metadata->'billing'->>'converts_to_plan') <> '', false))::boolean AS is_trial,
       pv.id AS plan_version_id, coalesce(pv.included_storage_gb, 0)::integer AS included_storage_gb
FROM billing_products bp
LEFT JOIN plans p ON bp.catalog_type = 'plan' AND p.code = bp.catalog_ref
LEFT JOIN plan_versions pv ON pv.id = p.current_version_id
WHERE bp.code = $1 AND bp.provider = 'polar' AND bp.active
	AND (bp.catalog_type <> 'plan' OR p.active);

-- name: ListBillingPlanProducts :many
SELECT bp.code, p.code AS plan_code, p.name AS plan_name, pv.included_credits::text AS included_credits, pv.included_storage_gb, pv.metadata
FROM billing_products bp JOIN plans p ON p.code = bp.catalog_ref JOIN plan_versions pv ON pv.id = p.current_version_id
WHERE bp.provider = 'polar' AND bp.catalog_type = 'plan' AND bp.active AND p.active
ORDER BY p.code, bp.code;

-- name: GetBillingAddonProduct :one
SELECT code, catalog_type, catalog_ref, provider_product_id, provider_price_id
FROM billing_products
WHERE provider = 'polar' AND active AND catalog_type = sqlc.arg(catalog_type) AND catalog_ref = sqlc.arg(catalog_ref)
ORDER BY updated_at DESC LIMIT 1;

-- name: GetCreditTopupUnit :one
SELECT code, catalog_ref, provider_product_id FROM billing_products
WHERE provider = 'polar' AND active AND catalog_type = 'credit_topup'
ORDER BY updated_at DESC LIMIT 1;

-- name: ReserveBillingPortalOperation :one
INSERT INTO billing_portal_operations (idempotency_key,user_id,request_hash)
VALUES (sqlc.arg(idempotency_key),sqlc.arg(user_id),sqlc.arg(request_hash))
ON CONFLICT (idempotency_key) DO UPDATE SET state='pending',last_error=NULL,updated_at=now()
WHERE billing_portal_operations.state='failed'
  AND billing_portal_operations.user_id=EXCLUDED.user_id
  AND billing_portal_operations.request_hash=EXCLUDED.request_hash
RETURNING *;

-- name: GetBillingPortalOperation :one
SELECT * FROM billing_portal_operations WHERE idempotency_key=$1;

-- name: CompleteBillingPortalOperation :execrows
UPDATE billing_portal_operations SET state='succeeded',result_ciphertext=sqlc.arg(result_ciphertext),last_error=NULL,updated_at=now()
WHERE idempotency_key=sqlc.arg(idempotency_key) AND state='pending';

-- name: MarkBillingPortalOperation :execrows
UPDATE billing_portal_operations SET state=sqlc.arg(state),last_error=sqlc.arg(last_error),updated_at=now()
WHERE idempotency_key=sqlc.arg(idempotency_key) AND state='pending';

-- name: ReserveBillingSubscriptionUpdate :one
INSERT INTO billing_subscription_update_operations (idempotency_key,user_id,provider_subscription_id,request_hash)
VALUES (sqlc.arg(idempotency_key),sqlc.arg(user_id),sqlc.arg(provider_subscription_id),sqlc.arg(request_hash))
ON CONFLICT (idempotency_key) DO UPDATE SET state='pending',last_error=NULL,updated_at=now()
WHERE billing_subscription_update_operations.state='failed'
  AND billing_subscription_update_operations.user_id=EXCLUDED.user_id
  AND billing_subscription_update_operations.provider_subscription_id=EXCLUDED.provider_subscription_id
  AND billing_subscription_update_operations.request_hash=EXCLUDED.request_hash
RETURNING *;

-- name: GetBillingSubscriptionUpdate :one
SELECT * FROM billing_subscription_update_operations WHERE idempotency_key=$1;

-- name: MarkBillingSubscriptionUpdate :execrows
UPDATE billing_subscription_update_operations SET state=sqlc.arg(state),last_error=sqlc.arg(last_error),updated_at=now()
WHERE idempotency_key=sqlc.arg(idempotency_key) AND state='pending';

-- name: GetBillingUncertainMetrics :one
SELECT
  (SELECT count(*) FROM billing_checkout_reservations WHERE state='uncertain')::bigint AS checkout_uncertain,
  (SELECT count(*) FROM billing_portal_operations WHERE state='uncertain')::bigint AS portal_uncertain,
  (SELECT count(*) FROM billing_subscription_update_operations WHERE state='uncertain')::bigint AS subscription_update_uncertain,
  (SELECT count(*) FROM credit_auto_topup_attempts WHERE state='uncertain')::bigint AS auto_topup_uncertain;

-- name: ReserveBillingUncertainRecovery :one
INSERT INTO billing_uncertain_recoveries (idempotency_key,operation_kind,operation_id,request_hash,actor_user_id)
VALUES (sqlc.arg(idempotency_key),sqlc.arg(operation_kind),sqlc.arg(operation_id),sqlc.arg(request_hash),sqlc.narg(actor_user_id))
ON CONFLICT (idempotency_key) DO NOTHING
RETURNING *;

-- name: GetBillingUncertainRecovery :one
SELECT * FROM billing_uncertain_recoveries WHERE idempotency_key=$1;

-- name: RecoverUncertainBillingCheckout :execrows
UPDATE billing_checkout_reservations SET state='failed',last_error='operator_evidence_no_mutation',updated_at=now()
WHERE idempotency_key=$1 AND state='uncertain';

-- name: RecoverUncertainBillingPortal :execrows
UPDATE billing_portal_operations SET state='failed',last_error='operator_evidence_no_mutation',updated_at=now()
WHERE idempotency_key=$1 AND state='uncertain';

-- name: RecoverUncertainBillingSubscriptionUpdate :execrows
UPDATE billing_subscription_update_operations SET state='failed',last_error='operator_evidence_no_mutation',updated_at=now()
WHERE idempotency_key=$1 AND state='uncertain';

-- name: RecoverUncertainBillingAutoTopup :execrows
UPDATE credit_auto_topup_attempts SET state='failed',last_error='operator_evidence_no_mutation',updated_at='epoch'::timestamptz
WHERE idempotency_key=$1 AND state='uncertain';

-- name: GetBillingProductByProviderIDs :one
SELECT code, catalog_type, catalog_ref, provider_product_id, provider_price_id
FROM billing_products
WHERE provider = 'polar' AND active
  AND provider_product_id = sqlc.arg(provider_product_id)
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
       ,coalesce((pv.metadata->'billing'->>'storage_unit_gb')::integer, 0)::integer AS storage_unit_gb
       ,coalesce((pv.metadata->'billing'->>'storage_seat_offset')::integer, 0)::integer AS storage_seat_offset
FROM plans p JOIN plan_versions pv ON pv.id = p.current_version_id WHERE p.code = $1 AND p.active;

-- name: GetConvertedTrialPlanVersionForWebhook :one
SELECT target_p.code, target_pv.id, target_pv.included_credits::text AS included_credits,
       target_pv.included_storage_gb,
       coalesce((target_pv.metadata->'billing'->>'storage_unit_gb')::integer, 0)::integer AS storage_unit_gb,
       coalesce((target_pv.metadata->'billing'->>'storage_seat_offset')::integer, 0)::integer AS storage_seat_offset
FROM plans trial_p
JOIN plan_versions trial_pv ON trial_pv.id = trial_p.current_version_id
JOIN plans target_p ON target_p.code = trial_pv.metadata->'billing'->>'converts_to_plan'
JOIN plan_versions target_pv ON target_pv.id = target_p.current_version_id
WHERE trial_p.code = $1 AND trial_p.active AND target_p.active;

-- name: GetPolarSubscriptionForUpdate :one
SELECT s.id, s.active_plan_version_id, pv.included_credits::text AS included_credits,
       s.current_period_start, s.current_period_end, s.storage_units
FROM subscriptions s
LEFT JOIN plan_versions pv ON pv.id = s.active_plan_version_id
WHERE s.provider = 'polar'
  AND s.provider_subscription_id = sqlc.arg(provider_subscription_id)
  AND s.user_id = sqlc.arg(user_id)
FOR UPDATE OF s;

-- name: HasSubscriptionPeriodCredits :one
SELECT EXISTS (
  SELECT 1
  FROM credit_ledger_entries cle
  JOIN credit_accounts ca ON ca.id = cle.account_id
  WHERE ca.user_id = sqlc.arg(user_id)
    AND cle.source_type = 'polar_subscription'
    AND cle.source_id = sqlc.arg(provider_subscription_id)
    AND cle.idempotency_key LIKE sqlc.arg(period_key_prefix)::text || '%'
);

-- name: UpsertPolarSubscription :exec
INSERT INTO subscriptions (id, user_id, provider, provider_subscription_id, state, active_plan_version_id, current_period_start, current_period_end, storage_units, pending_storage_units)
VALUES (sqlc.arg(id), sqlc.arg(user_id), 'polar', sqlc.arg(provider_subscription_id), sqlc.arg(state), sqlc.arg(active_plan_version_id), sqlc.narg(current_period_start), sqlc.narg(current_period_end), coalesce(sqlc.narg(storage_units), 0), sqlc.narg(pending_storage_units))
ON CONFLICT (provider_subscription_id) DO UPDATE SET
	user_id = EXCLUDED.user_id, state = EXCLUDED.state, active_plan_version_id = EXCLUDED.active_plan_version_id,
	current_period_start = EXCLUDED.current_period_start, current_period_end = EXCLUDED.current_period_end,
	storage_units = EXCLUDED.storage_units, pending_storage_units = EXCLUDED.pending_storage_units,
	version = subscriptions.version + 1, updated_at = now();

-- name: UpdateSubscriptionStorage :exec
UPDATE subscriptions SET storage_units = sqlc.arg(storage_units), pending_storage_units = sqlc.narg(pending_storage_units), version = version + 1, updated_at = now()
WHERE provider = 'polar' AND provider_subscription_id = sqlc.arg(provider_subscription_id) AND user_id = sqlc.arg(user_id);

-- name: SetPendingSubscriptionStorage :exec
UPDATE subscriptions SET pending_storage_units=sqlc.narg(pending_storage_units), version=version+1, updated_at=now()
WHERE provider='polar' AND provider_subscription_id=sqlc.arg(provider_subscription_id) AND user_id=sqlc.arg(user_id);

-- name: GetCreditAutoTopupPolicy :one
SELECT p.id, p.user_id, p.enabled, p.threshold::text, p.bundle_credits::text, p.provider_product_id,
       coalesce(a.state, '') AS last_attempt_state, coalesce(a.updated_at, 'epoch'::timestamptz) AS last_attempt_at, coalesce(a.last_error, '') AS last_error
FROM credit_auto_topup_policies p
LEFT JOIN LATERAL (SELECT state, updated_at, last_error FROM credit_auto_topup_attempts WHERE user_id = p.user_id ORDER BY updated_at DESC LIMIT 1) a ON true
WHERE p.user_id = $1;

-- name: UpsertCreditAutoTopupPolicy :exec
INSERT INTO credit_auto_topup_policies (id, user_id, enabled, threshold, bundle_credits, provider_product_id)
VALUES (sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(enabled), sqlc.arg(threshold)::numeric, sqlc.arg(bundle_credits)::numeric, sqlc.arg(provider_product_id))
ON CONFLICT (user_id) DO UPDATE SET enabled = EXCLUDED.enabled, threshold = EXCLUDED.threshold,
 bundle_credits = EXCLUDED.bundle_credits, provider_product_id = EXCLUDED.provider_product_id, updated_at = now();

-- name: DisableCreditAutoTopupPolicy :exec
UPDATE credit_auto_topup_policies SET enabled = false, updated_at = now() WHERE user_id = $1;

-- name: ReserveCreditAutoTopup :execrows
INSERT INTO credit_auto_topup_attempts (id, user_id, idempotency_key)
VALUES (sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(idempotency_key))
ON CONFLICT (idempotency_key) DO UPDATE SET state = 'reserved', updated_at = now()
WHERE credit_auto_topup_attempts.state = 'failed'
  AND credit_auto_topup_attempts.updated_at <= now() - make_interval(secs => sqlc.arg(retry_cooldown_seconds)::integer);

-- name: CompleteCreditAutoTopup :exec
UPDATE credit_auto_topup_attempts SET provider_order_id = sqlc.arg(provider_order_id), state = sqlc.arg(state), last_error = sqlc.arg(last_error), updated_at = now() WHERE idempotency_key = sqlc.arg(idempotency_key);

-- name: ListEligibleCreditAutoTopups :many
SELECT p.user_id, p.bundle_credits::text, p.provider_product_id, ca.version AS credit_version
FROM credit_auto_topup_policies p
JOIN credit_accounts ca ON ca.user_id = p.user_id
WHERE p.enabled AND ca.balance <= p.threshold
  AND EXISTS (SELECT 1 FROM subscriptions s WHERE s.user_id = p.user_id AND s.state IN ('active','trialing') AND (s.current_period_end IS NULL OR s.current_period_end > now()))
  AND NOT EXISTS (SELECT 1 FROM credit_auto_topup_attempts a WHERE a.idempotency_key = 'credit-auto:' || p.user_id || ':' || ca.version::text AND a.state IN ('reserved','created','paid'));

-- name: UserHasPolarSubscriptionHistory :one
SELECT EXISTS (SELECT 1 FROM subscriptions WHERE user_id = $1 AND provider = 'polar');

-- name: ReserveBillingCheckout :one
INSERT INTO billing_checkout_reservations (id, user_id, product_code, idempotency_key, expires_at)
VALUES (sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(product_code), sqlc.arg(idempotency_key), sqlc.arg(expires_at))
ON CONFLICT (user_id) DO UPDATE SET id=EXCLUDED.id, product_code=EXCLUDED.product_code,
 idempotency_key=EXCLUDED.idempotency_key, provider_checkout_id=NULL, checkout_url=NULL,
 state='reserved', expires_at=EXCLUDED.expires_at, last_error=NULL, uncertain_at=NULL, updated_at=now()
WHERE billing_checkout_reservations.state IN ('failed','completed')
   OR (billing_checkout_reservations.state = 'reserved' AND billing_checkout_reservations.expires_at <= now())
RETURNING id, product_code, idempotency_key, provider_checkout_id, checkout_url, state, expires_at;

-- name: GetBillingCheckoutReservation :one
SELECT id, product_code, idempotency_key, provider_checkout_id, checkout_url, state, expires_at
FROM billing_checkout_reservations WHERE user_id = $1;

-- name: CompleteBillingCheckoutReservation :exec
UPDATE billing_checkout_reservations SET provider_checkout_id=sqlc.arg(provider_checkout_id), checkout_url=sqlc.arg(checkout_url), updated_at=now()
WHERE user_id=sqlc.arg(user_id) AND idempotency_key=sqlc.arg(idempotency_key) AND state='reserved';

-- name: FailBillingCheckoutReservation :exec
UPDATE billing_checkout_reservations SET state='failed', last_error=NULL, updated_at=now() WHERE user_id=$1 AND state='reserved';

-- name: MarkBillingCheckoutUncertain :execrows
UPDATE billing_checkout_reservations
SET state='uncertain', last_error=sqlc.arg(last_error), uncertain_at=sqlc.arg(now), updated_at=sqlc.arg(now)
WHERE user_id=sqlc.arg(user_id) AND idempotency_key=sqlc.arg(idempotency_key) AND state='reserved';

-- name: ClearBillingCheckoutReservation :exec
UPDATE billing_checkout_reservations SET state='completed', updated_at=now() WHERE user_id=$1 AND state='reserved';

-- name: SetPendingSubscriptionPlan :exec
UPDATE subscriptions SET pending_plan_version_id=sqlc.narg(pending_plan_version_id), version=version+1, updated_at=now()
WHERE provider='polar' AND provider_subscription_id=sqlc.arg(provider_subscription_id) AND user_id=sqlc.arg(user_id);

-- name: ClearAppliedPendingSubscriptionPlan :exec
UPDATE subscriptions SET pending_plan_version_id=NULL, version=version+1, updated_at=now()
WHERE provider='polar' AND provider_subscription_id=$1 AND pending_plan_version_id=active_plan_version_id;

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
