-- +goose Up

SET LOCAL search_path TO paperboat;

ALTER TABLE users ADD COLUMN IF NOT EXISTS role text NOT NULL DEFAULT 'user';

-- +goose StatementBegin
DO $$
BEGIN
	IF NOT EXISTS (
		SELECT 1 FROM pg_constraint
		WHERE conname = 'users_role_valid'
		  AND conrelid = 'paperboat.users'::regclass
	) THEN
		ALTER TABLE users ADD CONSTRAINT users_role_valid CHECK (role IN ('user', 'support', 'admin', 'system_worker'));
	END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
-- Forward-only migration.
