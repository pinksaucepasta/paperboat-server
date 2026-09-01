-- +goose Up

-- Revocation is terminal and must remain distinguishable from ordinary
-- replacement retirement. The edge row is retained as an auditable binding,
-- but never contains certificate or private-key material.
ALTER TABLE tunnel_certificate_edge_distributions
  DROP CONSTRAINT IF EXISTS tunnel_certificate_edge_distributions_state_check;
ALTER TABLE tunnel_certificate_edge_distributions
  ADD CONSTRAINT tunnel_certificate_edge_distributions_state_check
  CHECK (state IN ('staged','ready','active','retired','revoked','failed'));

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM tunnel_certificate_edge_distributions WHERE state = 'revoked'
  ) THEN
    RAISE EXCEPTION 'cannot roll back edge revocation while revoked distribution exists';
  END IF;
END
$$;
-- +goose StatementEnd

ALTER TABLE tunnel_certificate_edge_distributions
  DROP CONSTRAINT IF EXISTS tunnel_certificate_edge_distributions_state_check;
ALTER TABLE tunnel_certificate_edge_distributions
  ADD CONSTRAINT tunnel_certificate_edge_distributions_state_check
  CHECK (state IN ('staged','ready','active','retired','failed'));
