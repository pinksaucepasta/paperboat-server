-- +goose Up
CREATE TABLE environment_vault_personal_rotations (
 account_id text PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 operation_id text NOT NULL, expected_vault_document_id text NOT NULL,
 UNIQUE(account_id,operation_id)
);
CREATE TABLE environment_vault_personal_rotation_scopes (
 account_id text NOT NULL, operation_id text NOT NULL, machine_id text NOT NULL DEFAULT '',
 document_id text NOT NULL CHECK(document_id ~ '^sha256:[0-9a-f]{64}$'),
 envelope bytea NOT NULL CHECK(octet_length(envelope) BETWEEN 1 AND 264192),
 PRIMARY KEY(account_id,machine_id),
 FOREIGN KEY(account_id,operation_id) REFERENCES environment_vault_personal_rotations(account_id,operation_id) ON DELETE CASCADE
);
-- A stage is useful only while its exact vault predecessor remains current.
-- Expire it atomically on any successor publication, including password/team writes.
-- +goose StatementBegin
CREATE FUNCTION expire_environment_personal_rotation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 DELETE FROM environment_vault_personal_rotations WHERE account_id=NEW.account_id AND expected_vault_document_id<>NEW.document_id;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER environment_personal_rotation_expiry AFTER UPDATE OF document_id ON environment_password_vaults FOR EACH ROW WHEN(OLD.document_id IS DISTINCT FROM NEW.document_id) EXECUTE FUNCTION expire_environment_personal_rotation();
-- +goose Down
DROP TRIGGER environment_personal_rotation_expiry ON environment_password_vaults;
DROP FUNCTION expire_environment_personal_rotation();
DROP TABLE environment_vault_personal_rotation_scopes;
DROP TABLE environment_vault_personal_rotations;
