-- +goose Up

-- The stable edge node ID survives an edge process replacement. Persist the
-- opaque process epoch beside every attachment so a stale process cannot
-- acknowledge or observe a replacement's route.
ALTER TABLE preview_lease_carrier_attachments
  ADD COLUMN edge_process_epoch text;

UPDATE preview_lease_carrier_attachments AS attachment
SET edge_process_epoch = node.process_epoch
FROM control_tunnel_nodes AS node
WHERE node.id = attachment.edge_node_id;

ALTER TABLE preview_lease_carrier_attachments
  ALTER COLUMN edge_process_epoch SET NOT NULL,
  ADD CONSTRAINT preview_lease_carrier_attachments_edge_process_epoch_check
    CHECK (length(edge_process_epoch) BETWEEN 8 AND 128 AND edge_process_epoch ~ '^[A-Za-z0-9_-]+$');

-- Existing outbox rows predate the explicit column and carry their binding in
-- JSON. Backfill the immutable process fence before requiring it on every
-- safe edge command.
UPDATE preview_carrier_attachment_outbox AS outbox
SET binding = jsonb_set(outbox.binding, '{edge_process_epoch}', to_jsonb(attachment.edge_process_epoch), true)
FROM preview_lease_carrier_attachments AS attachment
WHERE attachment.account_id = outbox.account_id
  AND attachment.operation_id = outbox.operation_id
  AND outbox.binding->>'edge_process_epoch' IS NULL;

ALTER TABLE preview_carrier_attachment_outbox
  ADD CONSTRAINT preview_carrier_attachment_outbox_edge_process_epoch_check
    CHECK (
      binding ? 'edge_process_epoch'
      AND length(binding->>'edge_process_epoch') BETWEEN 8 AND 128
      AND (binding->>'edge_process_epoch') ~ '^[A-Za-z0-9_-]+$'
    );

-- +goose StatementBegin
CREATE FUNCTION preview_lease_carrier_attachment_edge_epoch_guard_v1()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.state NOT IN ('failed','released') AND NOT EXISTS (
    SELECT 1
    FROM control_tunnel_nodes AS node
    WHERE node.id = NEW.edge_node_id
      AND node.process_epoch = NEW.edge_process_epoch
  ) THEN
    RAISE EXCEPTION 'preview attachment edge process epoch is stale';
  END IF;
  RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER preview_lease_carrier_attachment_edge_epoch_guard
  BEFORE INSERT OR UPDATE ON preview_lease_carrier_attachments
  FOR EACH ROW EXECUTE FUNCTION preview_lease_carrier_attachment_edge_epoch_guard_v1();

-- +goose Down

DROP TRIGGER IF EXISTS preview_lease_carrier_attachment_edge_epoch_guard ON preview_lease_carrier_attachments;
DROP FUNCTION IF EXISTS preview_lease_carrier_attachment_edge_epoch_guard_v1();
ALTER TABLE preview_carrier_attachment_outbox
  DROP CONSTRAINT IF EXISTS preview_carrier_attachment_outbox_edge_process_epoch_check;
ALTER TABLE preview_lease_carrier_attachments
  DROP CONSTRAINT IF EXISTS preview_lease_carrier_attachments_edge_process_epoch_check,
  DROP COLUMN IF EXISTS edge_process_epoch;
