-- +goose Up

-- A preview attachment is ephemeral binding metadata, not a tunnel
-- credential.  The row is bounded by the preview lease deadline and may be
-- recreated from a live machine proof and carrier session after a control
-- plane restart.  In particular, this table deliberately has no token,
-- bearer, password, private-key, or credential column.

-- Bind each preview lease to the one durable preview.create operation that
-- created it. Looking up the newest operation is unsafe: a later operation
-- with the same resource_id must never become the attachment authority.
CREATE TABLE preview_lease_create_operations (
  account_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  preview_id text NOT NULL,
  operation_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (account_id, preview_id),
  UNIQUE (account_id, operation_id),
  UNIQUE (account_id, preview_id, operation_id),
  FOREIGN KEY (preview_id, account_id)
    REFERENCES preview_leases(id, account_id) ON DELETE CASCADE,
  FOREIGN KEY (operation_id, account_id)
    REFERENCES operations(id, account_id) ON DELETE CASCADE
);

-- Existing development rows are backfilled from the oldest matching create
-- operation. New operation updates populate the relation immediately when
-- the preview store assigns resource_id during create completion.
INSERT INTO preview_lease_create_operations (account_id, preview_id, operation_id)
SELECT DISTINCT ON (p.account_id, p.id)
       p.account_id, p.id, o.id
FROM preview_leases AS p
JOIN operations AS o
  ON o.account_id = p.account_id
 AND o.resource_kind = 'preview_lease'
 AND o.resource_id = p.id
 AND o.operation_type = 'preview.create'
ORDER BY p.account_id, p.id, o.created_at ASC, o.id ASC
ON CONFLICT DO NOTHING;

-- +goose StatementBegin
CREATE FUNCTION preview_lease_create_operation_relation_v1()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.operation_type = 'preview.create'
     AND NEW.resource_kind = 'preview_lease'
     AND NEW.resource_id IS NOT NULL THEN
    INSERT INTO preview_lease_create_operations (account_id, preview_id, operation_id)
    SELECT NEW.account_id, NEW.resource_id, NEW.id
    WHERE EXISTS (
      SELECT 1 FROM preview_leases AS p
      WHERE p.id = NEW.resource_id AND p.account_id = NEW.account_id
    )
    ON CONFLICT DO NOTHING;
  END IF;
  RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER preview_lease_create_operation_relation
  AFTER INSERT OR UPDATE OF resource_id, resource_kind, operation_type ON operations
  FOR EACH ROW EXECUTE FUNCTION preview_lease_create_operation_relation_v1();

CREATE TABLE preview_lease_carrier_attachments (
  account_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  preview_id text NOT NULL,
  operation_id text NOT NULL,
  idempotency_key text NOT NULL,
  request_id text NOT NULL,
  correlation_id text NOT NULL,
  request_hash bytea NOT NULL,
  owner_device_id text NOT NULL,
  owner_session_id text NOT NULL,
  host_id text NOT NULL,
  edge_node_id text NOT NULL REFERENCES control_tunnel_nodes(id) ON DELETE RESTRICT,
  machine_identity_public_key text NOT NULL,
  machine_identity_thumbprint text NOT NULL,
  carrier_kind text NOT NULL DEFAULT 'preview_ephemeral',
  lease_generation bigint NOT NULL,
  tunnel_id text NOT NULL,
  connector_id text NOT NULL,
  connector_session_id text NOT NULL,
  process_generation bigint NOT NULL,
  config_generation bigint NOT NULL,
  route_id text NOT NULL,
  route_generation bigint NOT NULL,
  config_content_hash text NOT NULL,
  edge_endpoints text[] NOT NULL,
  attachment_generation bigint NOT NULL DEFAULT 1,
  state text NOT NULL DEFAULT 'pending',
  edge_ready boolean NOT NULL DEFAULT false,
  origin_ready boolean NOT NULL DEFAULT false,
  issued_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  ready_at timestamptz,
  released_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (account_id, operation_id),
  FOREIGN KEY (preview_id, account_id)
    REFERENCES preview_leases(id, account_id) ON DELETE CASCADE,
  FOREIGN KEY (operation_id, account_id)
    REFERENCES operations(id, account_id) ON DELETE CASCADE,
  FOREIGN KEY (account_id, preview_id, operation_id)
    REFERENCES preview_lease_create_operations(account_id, preview_id, operation_id) ON DELETE CASCADE,
  CHECK (octet_length(request_hash) = 32),
  CHECK (length(trim(idempotency_key)) BETWEEN 1 AND 256),
  CHECK (length(trim(request_id)) BETWEEN 3 AND 128),
  CHECK (length(trim(correlation_id)) BETWEEN 3 AND 128),
  CHECK (carrier_kind = 'preview_ephemeral'),
  CHECK (host_id = owner_device_id),
  CHECK (edge_node_id <> ''),
  CHECK (machine_identity_public_key ~ '^[A-Za-z0-9_-]{43}$'),
  CHECK (machine_identity_thumbprint ~ '^sha256:[A-Za-z0-9_-]{43}$'),
  CHECK (lease_generation > 0),
  CHECK (process_generation > 0),
  CHECK (config_generation > 0),
  CHECK (route_generation > 0),
  CHECK (config_content_hash ~ '^sha256:[0-9a-f]{64}$'),
  CHECK (cardinality(edge_endpoints) = 2),
  CHECK (attachment_generation > 0),
  CHECK (expires_at > issued_at),
  CHECK (state IN ('pending','admitted','edge_ready','ready','failed','released')),
  CHECK ((state = 'ready') = (edge_ready AND origin_ready)),
  CHECK (NOT origin_ready OR edge_ready),
  CHECK (state NOT IN ('pending','admitted') OR (NOT edge_ready AND NOT origin_ready)),
  CHECK (state <> 'edge_ready' OR (edge_ready AND NOT origin_ready)),
  CHECK ((state = 'released') = (released_at IS NOT NULL)),
  CHECK ((state = 'ready') = (ready_at IS NOT NULL)),
  CHECK (state <> 'released' OR NOT edge_ready AND NOT origin_ready)
);

-- A preview can have only one live operation binding.  A stopped/failed
-- operation remains replayable for audit and idempotency, while a later
-- operation may be allocated after it is terminal.
CREATE UNIQUE INDEX preview_lease_carrier_attachments_live_preview
  ON preview_lease_carrier_attachments(account_id, preview_id)
  WHERE state NOT IN ('failed','released');

CREATE UNIQUE INDEX preview_lease_carrier_attachments_idempotency
  ON preview_lease_carrier_attachments(account_id, idempotency_key);

CREATE INDEX preview_lease_carrier_attachments_expiry
  ON preview_lease_carrier_attachments(expires_at, account_id, operation_id)
  WHERE state NOT IN ('failed','released');

CREATE INDEX preview_lease_carrier_attachments_session
  ON preview_lease_carrier_attachments(connector_id, process_generation, connector_session_id)
  WHERE state NOT IN ('failed','released');

COMMENT ON TABLE preview_lease_carrier_attachments IS
  'Ephemeral preview-to-canonical-carrier binding metadata. Never stores bearer or private material.';
COMMENT ON COLUMN preview_lease_carrier_attachments.request_hash IS
  'SHA-256 of the canonical attachment request envelope; not secret material.';

-- Side effects are represented as durable, replayable work. The payload is
-- only the safe binding/admission metadata needed by the edge; it contains no
-- credential bytes. Admission is prepared before the publisher call, while
-- detach work is inserted in the same transaction as release/expiry.
CREATE TABLE preview_carrier_attachment_outbox (
  account_id text NOT NULL,
  operation_id text NOT NULL,
  attachment_generation bigint NOT NULL,
  action text NOT NULL,
  binding jsonb NOT NULL,
  config_content_hash text NOT NULL,
  edge_endpoints text[] NOT NULL,
  endpoint text NOT NULL,
  access_mode text NOT NULL,
  expires_at timestamptz NOT NULL,
  state text NOT NULL DEFAULT 'pending',
  attempts integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  last_error_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz,
  PRIMARY KEY (account_id, operation_id, attachment_generation, action),
  FOREIGN KEY (account_id, operation_id)
    REFERENCES preview_lease_carrier_attachments(account_id, operation_id) ON DELETE CASCADE,
  CHECK (attachment_generation > 0),
  CHECK (action IN ('admit','detach')),
  CHECK (jsonb_typeof(binding) = 'object'),
  CHECK (config_content_hash ~ '^sha256:[0-9a-f]{64}$'),
  CHECK (cardinality(edge_endpoints) = 2),
  CHECK (access_mode IN ('public','private')),
  CHECK (state IN ('pending','in_flight','delivered','failed')),
  CHECK (attempts >= 0),
  CHECK ((state = 'delivered') = (delivered_at IS NOT NULL))
);

CREATE INDEX preview_carrier_attachment_outbox_pending
  ON preview_carrier_attachment_outbox(next_attempt_at, created_at, account_id, operation_id)
  WHERE state IN ('pending','in_flight','failed');

COMMENT ON TABLE preview_carrier_attachment_outbox IS
  'Replayable edge admission/detach intents containing safe binding metadata only.';

-- owner_device_id is the canonical user machine recorded on the lease. This
-- trigger preserves the exact owner/session binding without weakening the
-- existing owner-session model.
-- +goose StatementBegin
CREATE FUNCTION preview_lease_carrier_attachment_guard_v1()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.state NOT IN ('failed','released') AND NOT EXISTS (
    SELECT 1
    FROM preview_leases AS p
    WHERE p.id = NEW.preview_id
      AND p.account_id = NEW.account_id
      AND p.owner_device_id = NEW.owner_device_id
      AND p.owner_session_id = NEW.owner_session_id
      AND p.terminal_state = 'active'
  ) THEN
    RAISE EXCEPTION 'preview attachment owner/session does not match active lease';
  END IF;
  IF NEW.state NOT IN ('failed','released') AND NOT EXISTS (
    SELECT 1
    FROM user_machines AS m
    WHERE m.id = NEW.owner_device_id
      AND m.user_id = NEW.account_id
      AND m.public_identity_key = NEW.machine_identity_public_key
      AND m.deleted_at IS NULL
      AND m.revoked_at IS NULL
  ) THEN
    RAISE EXCEPTION 'preview attachment machine verifier does not match owner machine';
  END IF;
  IF NEW.state IN ('failed','released') AND NOT EXISTS (
    SELECT 1
    FROM preview_leases AS p
    WHERE p.id = NEW.preview_id
      AND p.account_id = NEW.account_id
      AND p.owner_device_id = NEW.owner_device_id
      AND p.owner_session_id = NEW.owner_session_id
  ) THEN
    RAISE EXCEPTION 'preview attachment owner/session does not match lease';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM preview_lease_create_operations AS create_operation
    WHERE create_operation.account_id = NEW.account_id
      AND create_operation.preview_id = NEW.preview_id
      AND create_operation.operation_id = NEW.operation_id
  ) THEN
    RAISE EXCEPTION 'preview attachment operation does not own preview lease';
  END IF;
  RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER preview_lease_carrier_attachment_guard
  BEFORE INSERT OR UPDATE ON preview_lease_carrier_attachments
  FOR EACH ROW EXECUTE FUNCTION preview_lease_carrier_attachment_guard_v1();

-- +goose Down

DROP TRIGGER IF EXISTS preview_lease_carrier_attachment_guard ON preview_lease_carrier_attachments;
DROP FUNCTION IF EXISTS preview_lease_carrier_attachment_guard_v1();
DROP INDEX IF EXISTS preview_carrier_attachment_outbox_pending;
DROP TABLE IF EXISTS preview_carrier_attachment_outbox;
DROP TABLE IF EXISTS preview_lease_carrier_attachments;
DROP TRIGGER IF EXISTS preview_lease_create_operation_relation ON operations;
DROP FUNCTION IF EXISTS preview_lease_create_operation_relation_v1();
DROP TABLE IF EXISTS preview_lease_create_operations;
