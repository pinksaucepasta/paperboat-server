-- +goose Up
ALTER TABLE peer_network_identities
  ADD COLUMN disco_public_key bytea CHECK (disco_public_key IS NULL OR octet_length(disco_public_key) = 32);
CREATE UNIQUE INDEX peer_network_identity_disco_public_key
  ON peer_network_identities(disco_public_key) WHERE disco_public_key IS NOT NULL;
DROP TRIGGER identity_peer_network_generation ON peer_network_identities;
CREATE TRIGGER identity_peer_network_generation
AFTER UPDATE OF wireguard_public_key, disco_public_key, key_generation, quic_certificate_fingerprint, revoked_at
ON peer_network_identities FOR EACH ROW
EXECUTE FUNCTION advance_peer_network_for_identity();

ALTER TABLE control_tunnel_nodes
  ADD COLUMN peer_relay_wireguard_public_key bytea,
  ADD COLUMN peer_relay_disco_public_key bytea,
  ADD COLUMN peer_relay_virtual_address inet;
ALTER TABLE control_tunnel_nodes DROP CONSTRAINT control_tunnel_nodes_regional_registry_check;
ALTER TABLE control_tunnel_nodes ADD CONSTRAINT control_tunnel_nodes_regional_registry_check CHECK (
  (region IS NULL AND failure_domain IS NULL AND cardinality(roles)=0 AND cardinality(transports)=0 AND registry_expires_at IS NULL)
  OR (length(region) BETWEEN 1 AND 63 AND length(failure_domain) BETWEEN 1 AND 128
      AND cardinality(roles) BETWEEN 1 AND 2 AND roles <@ ARRAY['edge','relay','peer_relay']::text[]
      AND cardinality(transports) BETWEEN 1 AND 4 AND transports <@ ARRAY['http3','http2','derp_quic','derp_wss','peer_relay_udp']::text[]
      AND capacity_limit > 0 AND capacity_used <= capacity_limit
      AND capacity_observed_at IS NOT NULL AND registry_expires_at IS NOT NULL));
ALTER TABLE control_tunnel_nodes ADD CONSTRAINT control_tunnel_nodes_peer_relay_identity_check CHECK (
  (peer_relay_wireguard_public_key IS NULL AND peer_relay_disco_public_key IS NULL AND peer_relay_virtual_address IS NULL)
  OR (octet_length(peer_relay_wireguard_public_key) = 32
      AND octet_length(peer_relay_disco_public_key) = 32
      AND family(peer_relay_virtual_address) = 6
      AND peer_relay_virtual_address << inet 'fd7a:115c:a1e0::/48'
      AND roles @> ARRAY['relay','peer_relay']::text[]
      AND transports @> ARRAY['derp_quic','peer_relay_udp']::text[]));
CREATE UNIQUE INDEX control_tunnel_nodes_peer_relay_wireguard_key
  ON control_tunnel_nodes(peer_relay_wireguard_public_key) WHERE peer_relay_wireguard_public_key IS NOT NULL;
CREATE UNIQUE INDEX control_tunnel_nodes_peer_relay_disco_key
  ON control_tunnel_nodes(peer_relay_disco_public_key) WHERE peer_relay_disco_public_key IS NOT NULL;
CREATE UNIQUE INDEX control_tunnel_nodes_peer_relay_virtual_address
  ON control_tunnel_nodes(peer_relay_virtual_address) WHERE peer_relay_virtual_address IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS control_tunnel_nodes_peer_relay_virtual_address;
DROP INDEX IF EXISTS control_tunnel_nodes_peer_relay_disco_key;
DROP INDEX IF EXISTS control_tunnel_nodes_peer_relay_wireguard_key;
ALTER TABLE control_tunnel_nodes DROP CONSTRAINT IF EXISTS control_tunnel_nodes_peer_relay_identity_check;
ALTER TABLE control_tunnel_nodes DROP CONSTRAINT control_tunnel_nodes_regional_registry_check;
ALTER TABLE control_tunnel_nodes ADD CONSTRAINT control_tunnel_nodes_regional_registry_check CHECK (
  (region IS NULL AND failure_domain IS NULL AND cardinality(roles)=0 AND cardinality(transports)=0 AND registry_expires_at IS NULL)
  OR (length(region) BETWEEN 1 AND 63 AND length(failure_domain) BETWEEN 1 AND 128
      AND cardinality(roles) BETWEEN 1 AND 2 AND roles <@ ARRAY['edge','relay']::text[]
      AND cardinality(transports) BETWEEN 1 AND 4 AND transports <@ ARRAY['http3','http2','derp_quic','derp_wss']::text[]
      AND capacity_limit > 0 AND capacity_used <= capacity_limit
      AND capacity_observed_at IS NOT NULL AND registry_expires_at IS NOT NULL));
ALTER TABLE control_tunnel_nodes DROP COLUMN IF EXISTS peer_relay_virtual_address,
  DROP COLUMN IF EXISTS peer_relay_disco_public_key,
  DROP COLUMN IF EXISTS peer_relay_wireguard_public_key;
DROP INDEX IF EXISTS peer_network_identity_disco_public_key;
DROP TRIGGER identity_peer_network_generation ON peer_network_identities;
CREATE TRIGGER identity_peer_network_generation
AFTER UPDATE OF wireguard_public_key, key_generation, quic_certificate_fingerprint, revoked_at
ON peer_network_identities FOR EACH ROW
EXECUTE FUNCTION advance_peer_network_for_identity();
ALTER TABLE peer_network_identities DROP COLUMN IF EXISTS disco_public_key;
