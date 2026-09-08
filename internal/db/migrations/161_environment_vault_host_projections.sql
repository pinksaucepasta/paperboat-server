-- +goose Up
CREATE TABLE environment_vault_hosts (
 machine_id text PRIMARY KEY REFERENCES user_machines(id) ON DELETE CASCADE,
 account_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 installation_generation bigint NOT NULL CHECK(installation_generation BETWEEN 1 AND 9007199254740991),
 host_key_generation bigint NOT NULL CHECK(host_key_generation BETWEEN 1 AND 9007199254740991),
 host_public bytea NOT NULL CHECK(octet_length(host_public)=32),
 writer_public bytea NOT NULL CHECK(octet_length(writer_public)=32),
 selection_generation bigint NOT NULL DEFAULT 0 CHECK(selection_generation BETWEEN 0 AND 9007199254740991),
 selection bytea NOT NULL DEFAULT '\x5b5d' CHECK(octet_length(selection) BETWEEN 2 AND 65536),
 projection_revision bigint NOT NULL DEFAULT 0 CHECK(projection_revision BETWEEN 0 AND 9007199254740991),
 document_id text NOT NULL DEFAULT '' CHECK(document_id='' OR document_id ~ '^sha256:[0-9a-f]{64}$'),
 envelope bytea NOT NULL DEFAULT '' CHECK(octet_length(envelope)<=327680),
 applied_fence_generation bigint NOT NULL DEFAULT 0 CHECK(applied_fence_generation BETWEEN 0 AND 9007199254740991),
 observation_seq bigint NOT NULL DEFAULT 0 CHECK(observation_seq BETWEEN 0 AND 9007199254740991),
 observation_digest bytea,
 observation bytea CHECK(observation IS NULL OR octet_length(observation)<=4096)
);
-- +goose Down
DROP TABLE environment_vault_hosts;
