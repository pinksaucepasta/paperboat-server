-- +goose Up
-- TRK-07 closes the remaining duplicated-scope references introduced by the
-- resource tables. IDs remain opaque, but every account-bearing child now
-- proves that its operation belongs to the same account.
ALTER TABLE operations
  ADD CONSTRAINT operations_id_account_unique UNIQUE (id, account_id);

ALTER TABLE tunnel_connector_enrollments
  ADD CONSTRAINT tunnel_connector_enrollments_operation_account_fk
    FOREIGN KEY (operation_id, account_id)
    REFERENCES operations(id, account_id) ON DELETE RESTRICT,
  ADD CONSTRAINT tunnel_connector_enrollments_consumed_connector_check
    CHECK (connector_id IS NULL OR consumed_at IS NOT NULL);

CREATE INDEX tunnel_log_entries_resource_level_cursor
  ON tunnel_log_entries(account_id, tunnel_id, level, cursor_sequence ASC);

-- +goose Down
DROP INDEX IF EXISTS tunnel_log_entries_resource_level_cursor;
ALTER TABLE tunnel_connector_enrollments
  DROP CONSTRAINT IF EXISTS tunnel_connector_enrollments_consumed_connector_check,
  DROP CONSTRAINT IF EXISTS tunnel_connector_enrollments_operation_account_fk;
ALTER TABLE operations
  DROP CONSTRAINT IF EXISTS operations_id_account_unique;
