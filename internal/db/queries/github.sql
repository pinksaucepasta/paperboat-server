-- name: LinkGitHubIdentity :one
INSERT INTO user_identities (id, user_id, provider, provider_subject, email, created_at, updated_at)
VALUES ($1, $2, 'github', $3, '', now(), now())
ON CONFLICT (provider, provider_subject) DO UPDATE SET updated_at = now()
RETURNING user_id;

-- name: UpsertGitHubOAuthToken :exec
INSERT INTO github_oauth_tokens
	(id, user_id, token_ciphertext, refresh_token_ciphertext, scopes, expires_at, provider_account_login, last_validated_at, created_at, updated_at)
VALUES (sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(token_ciphertext), sqlc.arg(refresh_token_ciphertext), sqlc.arg(scopes), sqlc.narg(expires_at), sqlc.arg(provider_account_login), now(), now(), now())
ON CONFLICT (user_id) DO UPDATE SET
	token_ciphertext = EXCLUDED.token_ciphertext,
	refresh_token_ciphertext = EXCLUDED.refresh_token_ciphertext,
	scopes = EXCLUDED.scopes,
	expires_at = EXCLUDED.expires_at,
	provider_account_login = EXCLUDED.provider_account_login,
	revoked_at = NULL,
	last_validated_at = now(),
	updated_at = now(),
	version = github_oauth_tokens.version + 1;

-- name: GetGitHubConnectionStatus :one
SELECT scopes, last_validated_at, token_ciphertext FROM github_oauth_tokens
WHERE user_id = $1 AND revoked_at IS NULL ORDER BY updated_at DESC LIMIT 1;

-- name: GetGitHubConfigRepoStatus :one
SELECT owner, name, default_branch FROM github_config_repositories
WHERE user_id = $1 AND provisioned_at IS NOT NULL;

-- name: GetGitHubScopes :one
SELECT scopes FROM github_oauth_tokens
WHERE user_id = $1 AND revoked_at IS NULL ORDER BY updated_at DESC LIMIT 1;

-- name: GetGitHubToken :one
SELECT token_ciphertext, provider_account_login, scopes FROM github_oauth_tokens
WHERE user_id = $1 AND revoked_at IS NULL ORDER BY updated_at DESC LIMIT 1;

-- name: UpsertGitHubProvisioningAttempt :exec
INSERT INTO github_repo_provisioning_attempts (id, user_id, idempotency_key, state, repo_owner, repo_name, last_error, attempts, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, 1, now(), now())
ON CONFLICT (idempotency_key) DO UPDATE SET
	state = EXCLUDED.state, repo_owner = EXCLUDED.repo_owner, repo_name = EXCLUDED.repo_name,
	last_error = EXCLUDED.last_error, attempts = github_repo_provisioning_attempts.attempts + 1, updated_at = now();

-- name: UpsertGitHubConfigRepository :exec
INSERT INTO github_config_repositories (id, user_id, provider_repo_id, owner, name, default_branch, clone_url, html_url, private, provisioned_at, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now(), now(), now())
ON CONFLICT (user_id) DO UPDATE SET
	provider_repo_id = EXCLUDED.provider_repo_id, owner = EXCLUDED.owner, name = EXCLUDED.name,
	default_branch = EXCLUDED.default_branch, clone_url = EXCLUDED.clone_url, html_url = EXCLUDED.html_url,
	private = EXCLUDED.private, provisioned_at = now(), updated_at = now(), version = github_config_repositories.version + 1;

-- name: MarkGitHubProvisioningSucceeded :exec
UPDATE github_repo_provisioning_attempts SET state = 'succeeded', updated_at = now() WHERE idempotency_key = $1;
