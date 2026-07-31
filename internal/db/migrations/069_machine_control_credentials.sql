-- +goose Up
CREATE TABLE machine_control_renewals (
    operation_id text PRIMARY KEY,
    machine_id text NOT NULL REFERENCES user_machines(id) ON DELETE CASCADE,
    installation_generation bigint NOT NULL CHECK (installation_generation > 0),
    credential_jti text NOT NULL UNIQUE,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > issued_at),
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (length(operation_id) BETWEEN 8 AND 128)
);

CREATE INDEX machine_control_renewals_expiry_idx
    ON machine_control_renewals (expires_at);

-- +goose Down
SELECT 1;
