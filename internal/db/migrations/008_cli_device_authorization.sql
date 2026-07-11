-- +goose Up

SET LOCAL search_path TO paperboat;

CREATE TABLE device_grants (
	id text PRIMARY KEY,
	client_id text NOT NULL,
	client_label text NOT NULL,
	device_type text NOT NULL,
	os text NOT NULL,
	scopes text[] NOT NULL,
	device_code_hash text NOT NULL UNIQUE,
	user_code_hash text NOT NULL UNIQUE,
	state text NOT NULL CHECK (state IN ('pending','approved','denied','consumed','expired')),
	user_id text REFERENCES users(id),
	issued_at timestamptz NOT NULL,
	expires_at timestamptz NOT NULL,
	poll_interval_seconds integer NOT NULL,
	next_poll_at timestamptz NOT NULL,
	approved_at timestamptz,
	denied_at timestamptz,
	consumed_at timestamptz,
	created_network_hash text NOT NULL,
	version bigint NOT NULL DEFAULT 1
);
CREATE INDEX idx_device_grants_expiry ON device_grants(expires_at);

CREATE TABLE client_sessions (
	id text PRIMARY KEY,
	user_id text NOT NULL REFERENCES users(id),
	client_id text NOT NULL,
	client_label text NOT NULL,
	device_type text NOT NULL,
	os text NOT NULL,
	scopes text[] NOT NULL,
	state text NOT NULL CHECK (state IN ('active','revoked')),
	created_at timestamptz NOT NULL,
	approved_at timestamptz NOT NULL,
	last_used_at timestamptz,
	revoked_at timestamptz,
	revocation_reason text,
	version bigint NOT NULL DEFAULT 1
);
CREATE INDEX idx_client_sessions_user_created ON client_sessions(user_id, created_at DESC);

CREATE TABLE client_access_tokens (
	token_hash text PRIMARY KEY,
	client_session_id text NOT NULL REFERENCES client_sessions(id) ON DELETE CASCADE,
	expires_at timestamptz NOT NULL,
	created_at timestamptz NOT NULL,
	revoked_at timestamptz
);
CREATE INDEX idx_client_access_tokens_session ON client_access_tokens(client_session_id);

CREATE TABLE client_refresh_tokens (
	token_hash text PRIMARY KEY,
	client_session_id text NOT NULL REFERENCES client_sessions(id) ON DELETE CASCADE,
	state text NOT NULL CHECK (state IN ('active','rotated','revoked')),
	expires_at timestamptz NOT NULL,
	created_at timestamptz NOT NULL,
	rotated_at timestamptz,
	revoked_at timestamptz
);
CREATE UNIQUE INDEX idx_client_refresh_tokens_one_active ON client_refresh_tokens(client_session_id) WHERE state = 'active';

CREATE TABLE auth_rate_limits (
	bucket_key text NOT NULL,
	window_start timestamptz NOT NULL,
	request_count integer NOT NULL,
	PRIMARY KEY (bucket_key, window_start)
);
CREATE INDEX idx_auth_rate_limits_window ON auth_rate_limits(window_start);

-- +goose Down
-- Forward-only migration.
