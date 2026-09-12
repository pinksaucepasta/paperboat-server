-- +goose Up
CREATE TABLE team_inbox_policies (
  account_id text PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  acceptance text NOT NULL DEFAULT 'manual' CHECK (acceptance IN ('manual','automatic')),
  receipt_email boolean NOT NULL DEFAULT false,
  generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE team_inbox_sender_policies (
  recipient_account text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  sender_account text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  acceptance text NOT NULL CHECK (acceptance IN ('manual','automatic')),
  generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (recipient_account, sender_account),
  CHECK (recipient_account <> sender_account)
);

CREATE TABLE team_inbox_requests (
  request_id text PRIMARY KEY,
  operation_id text NOT NULL,
  team_id text NOT NULL REFERENCES teams(team_id),
  sender_account text NOT NULL REFERENCES users(id),
  recipient_account text NOT NULL REFERENCES users(id),
  source_machine_id text NOT NULL REFERENCES user_machines(id),
  destination_machine_id text NOT NULL REFERENCES user_machines(id),
  batch_id text NOT NULL,
  manifest_digest text NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
  manifest jsonb NOT NULL CHECK (jsonb_typeof(manifest)='array' AND jsonb_array_length(manifest) BETWEEN 1 AND 10 AND octet_length(manifest::text) <= 16384),
  status text NOT NULL CHECK (status IN ('pending','approved','declined','expired','revoked','consumed','completed')),
  decision_kind text NOT NULL CHECK (decision_kind IN ('manual','automatic')),
  policy_generation bigint NOT NULL CHECK (policy_generation > 0),
  decision_generation bigint NOT NULL DEFAULT 1 CHECK (decision_generation > 0),
  expires_at timestamptz NOT NULL,
  decided_at timestamptz,
  consumed_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (sender_account, operation_id),
  UNIQUE (sender_account, batch_id),
  CHECK (sender_account <> recipient_account),
  CHECK (source_machine_id <> destination_machine_id)
);
CREATE INDEX team_inbox_requests_recipient_pending
  ON team_inbox_requests(recipient_account, created_at, request_id)
  WHERE status='pending';

CREATE TABLE team_inbox_receipt_outbox (
  request_id text PRIMARY KEY REFERENCES team_inbox_requests(request_id) ON DELETE CASCADE,
  recipient_account text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','delivering','delivered','failed')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  provider_message_id text,
  last_error_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX team_inbox_receipt_outbox_pending
  ON team_inbox_receipt_outbox(next_attempt_at, request_id)
  WHERE status IN ('pending','failed');

-- +goose Down
DROP TABLE team_inbox_receipt_outbox;
DROP TABLE team_inbox_requests;
DROP TABLE team_inbox_sender_policies;
DROP TABLE team_inbox_policies;
