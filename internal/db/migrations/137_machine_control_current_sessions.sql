-- +goose Up
ALTER TABLE machine_control_renewals
    ADD COLUMN session_generation bigint,
    ADD COLUMN superseded_at timestamptz,
    ADD CONSTRAINT machine_control_renewals_operation_machine_installation_unique
        UNIQUE (operation_id, machine_id, installation_generation),
    ADD CONSTRAINT machine_control_renewals_session_generation_positive
        CHECK (session_generation IS NULL OR session_generation > 0);

CREATE UNIQUE INDEX machine_control_renewals_machine_session_generation_idx
    ON machine_control_renewals (machine_id, session_generation)
    WHERE session_generation IS NOT NULL;

CREATE TABLE machine_control_sessions (
    machine_id text PRIMARY KEY REFERENCES user_machines(id) ON DELETE CASCADE,
    installation_generation bigint NOT NULL CHECK (installation_generation > 0),
    session_generation bigint NOT NULL CHECK (session_generation > 0),
    operation_id text NOT NULL,
    credential_jti text NOT NULL UNIQUE,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > issued_at),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (operation_id, machine_id, installation_generation)
        REFERENCES machine_control_renewals (operation_id, machine_id, installation_generation)
        ON DELETE RESTRICT,
    UNIQUE (machine_id, session_generation)
);

WITH latest AS (
    SELECT DISTINCT ON (machine_id)
        operation_id, machine_id, installation_generation, credential_jti, issued_at, expires_at
    FROM machine_control_renewals
    ORDER BY machine_id, issued_at DESC, created_at DESC, credential_jti DESC
), tagged AS (
    UPDATE machine_control_renewals renewals
    SET session_generation = 1
    FROM latest
    WHERE renewals.operation_id = latest.operation_id
    RETURNING renewals.operation_id
)
INSERT INTO machine_control_sessions (
    machine_id, installation_generation, session_generation, operation_id,
    credential_jti, issued_at, expires_at
)
SELECT machine_id, installation_generation, 1, operation_id,
       credential_jti, issued_at, expires_at
FROM latest;

UPDATE machine_control_renewals renewals
SET superseded_at = now()
WHERE renewals.session_generation IS NULL;

-- +goose Down
DROP TABLE IF EXISTS machine_control_sessions;
DROP INDEX IF EXISTS machine_control_renewals_machine_session_generation_idx;
ALTER TABLE machine_control_renewals
    DROP CONSTRAINT IF EXISTS machine_control_renewals_session_generation_positive,
    DROP CONSTRAINT IF EXISTS machine_control_renewals_operation_machine_installation_unique,
    DROP COLUMN IF EXISTS session_generation,
    DROP COLUMN IF EXISTS superseded_at;
