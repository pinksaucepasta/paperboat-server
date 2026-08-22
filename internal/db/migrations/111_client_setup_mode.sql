-- Canonical machine setup modes are host and client. Existing receive-mode
-- machines retain their behavior under the client name; session remains a
-- temporary terminal mode.
-- +goose Up
ALTER TABLE user_machines DROP CONSTRAINT user_machines_setup_mode_check;
UPDATE user_machines SET setup_mode = 'client' WHERE setup_mode = 'receive';
ALTER TABLE user_machines ADD CONSTRAINT user_machines_setup_mode_check CHECK (setup_mode IN ('client','session','host'));

-- +goose Down
ALTER TABLE user_machines DROP CONSTRAINT user_machines_setup_mode_check;
UPDATE user_machines SET setup_mode = 'receive' WHERE setup_mode = 'client';
ALTER TABLE user_machines ADD CONSTRAINT user_machines_setup_mode_check CHECK (setup_mode IN ('receive','session','host'));
