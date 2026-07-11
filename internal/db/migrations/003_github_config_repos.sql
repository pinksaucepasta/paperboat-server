-- +goose Up

SET LOCAL search_path TO paperboat;

ALTER TABLE github_oauth_tokens ADD COLUMN IF NOT EXISTS refresh_token_ciphertext bytea;
ALTER TABLE github_oauth_tokens ADD COLUMN IF NOT EXISTS provider_account_login text NOT NULL DEFAULT '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_github_oauth_tokens_user_unique ON github_oauth_tokens(user_id);

CREATE TABLE IF NOT EXISTS github_config_repositories (
	id text PRIMARY KEY,
	user_id text NOT NULL UNIQUE REFERENCES users(id),
	provider_repo_id text NOT NULL DEFAULT '',
	owner text NOT NULL,
	name text NOT NULL,
	default_branch text NOT NULL,
	clone_url text NOT NULL,
	html_url text NOT NULL DEFAULT '',
	private boolean NOT NULL DEFAULT true,
	provisioned_at timestamptz,
	version bigint NOT NULL DEFAULT 1,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE (owner, name)
);

CREATE TABLE IF NOT EXISTS github_repo_provisioning_attempts (
	id text PRIMARY KEY,
	user_id text NOT NULL REFERENCES users(id),
	idempotency_key text NOT NULL UNIQUE,
	state text NOT NULL,
	repo_owner text NOT NULL DEFAULT '',
	repo_name text NOT NULL DEFAULT '',
	last_error text NOT NULL DEFAULT '',
	attempts integer NOT NULL DEFAULT 0,
	next_retry_at timestamptz,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_github_oauth_tokens_user_id ON github_oauth_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_github_config_repositories_user_id ON github_config_repositories(user_id);

-- +goose Down
-- Forward-only migration.
