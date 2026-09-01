-- +goose Up
ALTER TABLE control_tunnel_nodes
  ADD COLUMN carrier_server_spki_sha256 text,
  ADD COLUMN carrier_server_certificate_chain_pem text;

ALTER TABLE control_tunnel_nodes
  ADD CONSTRAINT control_tunnel_nodes_carrier_server_spki_sha256_check CHECK (
    carrier_server_spki_sha256 IS NULL
    OR carrier_server_spki_sha256 ~ '^sha256:[0-9a-f]{64}$'
  );

ALTER TABLE control_tunnel_nodes
  ADD CONSTRAINT control_tunnel_nodes_carrier_server_certificate_chain_pem_check CHECK (
    carrier_server_certificate_chain_pem IS NULL
    OR octet_length(carrier_server_certificate_chain_pem) BETWEEN 1 AND 65536
  );

ALTER TABLE preview_lease_carrier_attachments
  ADD COLUMN edge_carrier_server_spki_sha256 text,
  ADD COLUMN edge_carrier_server_certificate_chain_pem text;

ALTER TABLE preview_lease_carrier_attachments
  ADD CONSTRAINT preview_lease_carrier_attachments_edge_carrier_spki_check CHECK (
    edge_carrier_server_spki_sha256 ~ '^sha256:[0-9a-f]{64}$'
  );

ALTER TABLE preview_lease_carrier_attachments
  ADD CONSTRAINT preview_lease_carrier_attachments_edge_carrier_chain_check CHECK (
    octet_length(edge_carrier_server_certificate_chain_pem) BETWEEN 1 AND 65536
  );

-- +goose Down
ALTER TABLE preview_lease_carrier_attachments
  DROP CONSTRAINT IF EXISTS preview_lease_carrier_attachments_edge_carrier_spki_check,
  DROP CONSTRAINT IF EXISTS preview_lease_carrier_attachments_edge_carrier_chain_check,
  DROP COLUMN IF EXISTS edge_carrier_server_certificate_chain_pem,
  DROP COLUMN IF EXISTS edge_carrier_server_spki_sha256;

ALTER TABLE control_tunnel_nodes
  DROP CONSTRAINT IF EXISTS control_tunnel_nodes_carrier_server_spki_sha256_check,
  DROP CONSTRAINT IF EXISTS control_tunnel_nodes_carrier_server_certificate_chain_pem_check,
  DROP COLUMN IF EXISTS carrier_server_certificate_chain_pem,
  DROP COLUMN IF EXISTS carrier_server_spki_sha256;
