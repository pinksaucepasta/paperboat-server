-- +goose Up

ALTER TABLE preview_leases
  DROP CONSTRAINT IF EXISTS preview_leases_target_scheme_check;

ALTER TABLE preview_leases
  ADD CONSTRAINT preview_leases_target_scheme_v1_check
    CHECK (target_scheme IN ('http','https','h2c','unix','tcp'));

-- +goose Down

ALTER TABLE preview_leases
  DROP CONSTRAINT IF EXISTS preview_leases_target_scheme_v1_check;

ALTER TABLE preview_leases
  ADD CONSTRAINT preview_leases_target_scheme_check
    CHECK (target_scheme IN ('http','https'));
