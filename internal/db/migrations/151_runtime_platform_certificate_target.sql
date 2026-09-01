-- +goose Up

ALTER TABLE tunnel_platform_certificate_targets
  DROP CONSTRAINT tunnel_platform_certificate_targets_id_check,
  DROP CONSTRAINT tunnel_platform_certificate_targets_kind_check,
  DROP CONSTRAINT tunnel_platform_certificate_targets_check,
  ADD CONSTRAINT tunnel_platform_certificate_targets_id_check
    CHECK (id IN ('platform_cert_preview_v1','platform_cert_tunnel_v1','platform_cert_runtime_v1')),
  ADD CONSTRAINT tunnel_platform_certificate_targets_kind_check
    CHECK (kind IN ('preview_wildcard','tunnel_wildcard','runtime_wildcard')),
  ADD CONSTRAINT tunnel_platform_certificate_targets_check
    CHECK ((id = 'platform_cert_preview_v1' AND kind = 'preview_wildcard')
        OR (id = 'platform_cert_tunnel_v1' AND kind = 'tunnel_wildcard')
        OR (id = 'platform_cert_runtime_v1' AND kind = 'runtime_wildcard'));

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM tunnel_platform_certificate_targets
    WHERE id = 'platform_cert_runtime_v1'
       OR kind = 'runtime_wildcard'
  ) OR EXISTS (
    SELECT 1
    FROM tunnel_certificate_records
    WHERE domain_id = 'platform_cert_runtime_v1'
  ) OR EXISTS (
    SELECT 1
    FROM tunnel_certificate_issuance_locks
    WHERE domain_id = 'platform_cert_runtime_v1'
  ) THEN
    RAISE EXCEPTION 'cannot remove runtime platform certificate target while runtime certificate state exists';
  END IF;

  ALTER TABLE tunnel_platform_certificate_targets
    DROP CONSTRAINT tunnel_platform_certificate_targets_id_check,
    DROP CONSTRAINT tunnel_platform_certificate_targets_kind_check,
    DROP CONSTRAINT tunnel_platform_certificate_targets_check,
    ADD CONSTRAINT tunnel_platform_certificate_targets_id_check
      CHECK (id IN ('platform_cert_preview_v1','platform_cert_tunnel_v1')),
    ADD CONSTRAINT tunnel_platform_certificate_targets_kind_check
      CHECK (kind IN ('preview_wildcard','tunnel_wildcard')),
    ADD CONSTRAINT tunnel_platform_certificate_targets_check
      CHECK ((id = 'platform_cert_preview_v1' AND kind = 'preview_wildcard')
          OR (id = 'platform_cert_tunnel_v1' AND kind = 'tunnel_wildcard'));
END;
$$;
-- +goose StatementEnd
