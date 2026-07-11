-- name: UpsertWorkOSUser :one
WITH upsert_user AS (
	INSERT INTO users (id, workos_subject, primary_email, display_name, status, created_at, updated_at)
	VALUES (sqlc.arg(user_id), sqlc.arg(workos_subject), sqlc.arg(primary_email), sqlc.arg(display_name), 'active', now(), now())
	ON CONFLICT (workos_subject) DO UPDATE SET primary_email = EXCLUDED.primary_email, display_name = EXCLUDED.display_name, updated_at = now(), version = users.version + 1
	RETURNING id, workos_subject, primary_email, display_name, status, role, created_at
), identity AS (
	INSERT INTO user_identities (id, user_id, provider, provider_subject, email, created_at, updated_at)
	SELECT sqlc.arg(identity_id), id, 'workos', workos_subject, primary_email, now(), now() FROM upsert_user
	ON CONFLICT (provider, provider_subject) DO UPDATE SET email = EXCLUDED.email, updated_at = now()
)
SELECT id, workos_subject, primary_email, display_name, status, role, created_at FROM upsert_user;

-- name: CreateBrowserSession :exec
INSERT INTO sessions (id, user_id, session_hash, csrf_hash, expires_at, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, now(), now());

-- name: AuthenticateBrowserSession :one
SELECT s.id AS session_id, s.user_id, s.expires_at, s.csrf_hash,
       u.id, u.workos_subject, u.primary_email, u.display_name, u.status, u.role, u.created_at
FROM sessions s JOIN users u ON u.id = s.user_id
WHERE s.session_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > now() AND u.status = 'active';

-- name: RotateBrowserSession :execrows
UPDATE sessions SET session_hash = sqlc.arg(session_hash), csrf_hash = sqlc.arg(csrf_hash), expires_at = sqlc.arg(expires_at),
	rotated_at = now(), updated_at = now(), version = version + 1
WHERE id = sqlc.arg(id) AND revoked_at IS NULL AND expires_at > now();

-- name: RefreshBrowserSessionCSRF :execrows
UPDATE sessions SET csrf_hash = sqlc.arg(csrf_hash), updated_at = now()
WHERE id = sqlc.arg(id) AND revoked_at IS NULL AND expires_at > now();

-- name: RevokeBrowserSession :one
UPDATE sessions SET revoked_at = now(), updated_at = now(), version = version + 1
WHERE session_hash = $1 AND revoked_at IS NULL RETURNING user_id;

-- name: BrowserSessionCSRFExists :one
SELECT EXISTS (SELECT 1 FROM sessions WHERE session_hash = $1 AND csrf_hash = $2 AND revoked_at IS NULL AND expires_at > now());

-- name: UserHasActiveSubscription :one
SELECT EXISTS (SELECT 1 FROM subscriptions WHERE user_id = $1 AND state IN ('active', 'trialing') AND (current_period_end IS NULL OR current_period_end > now()));

-- name: GetFreePlanEntitlement :one
SELECT pv.id, pv.included_credits::text AS included_credits, pv.included_storage_gb
FROM plans p JOIN plan_versions pv ON pv.id = p.current_version_id
WHERE p.code = 'free' AND p.active LIMIT 1;

-- name: UserOwnsProject :one
SELECT EXISTS (SELECT 1 FROM projects WHERE id = $1 AND user_id = $2 AND state <> 'deleted');

-- name: EnsureCreditAccount :one
INSERT INTO credit_accounts (id, user_id) VALUES ($1, $2)
ON CONFLICT (user_id) DO UPDATE SET updated_at = credit_accounts.updated_at RETURNING id;

-- name: EnsureStorageAccount :one
INSERT INTO storage_accounts (id, user_id) VALUES ($1, $2)
ON CONFLICT (user_id) DO UPDATE SET updated_at = storage_accounts.updated_at RETURNING id;

-- name: CreditLedgerEntryExists :one
SELECT EXISTS (SELECT 1 FROM credit_ledger_entries WHERE idempotency_key = $1);

-- name: InsertFreeCreditGrant :execrows
INSERT INTO credit_ledger_entries (id, account_id, entry_type, amount, source_type, source_id, idempotency_key, metadata)
VALUES (sqlc.arg(id), sqlc.arg(account_id), 'grant', sqlc.arg(amount)::numeric, 'plan', sqlc.arg(source_id), sqlc.arg(idempotency_key), '{"plan_code":"free"}'::jsonb)
ON CONFLICT (idempotency_key) DO NOTHING;

-- name: IncreaseCreditBalance :exec
UPDATE credit_accounts SET balance = balance + sqlc.arg(amount)::numeric, version = version + 1, updated_at = now() WHERE id = sqlc.arg(id);

-- name: GetStorageUsageForUpdate :one
SELECT purchased_gb, allocated_gb FROM storage_accounts WHERE id = $1 FOR UPDATE;

-- name: SetIncludedStorage :exec
UPDATE storage_accounts SET included_gb = $2, version = version + 1, updated_at = now() WHERE id = $1;

-- name: InsertFreeIncludedStorageLedger :execrows
INSERT INTO storage_ledger_entries (id, account_id, entry_type, amount_gb, source_type, source_id, idempotency_key, metadata)
VALUES ($1, $2, 'included_set', $3, 'plan', $4, $5, '{"plan_code":"free"}'::jsonb)
ON CONFLICT (idempotency_key) DO NOTHING;
