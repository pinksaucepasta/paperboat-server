-- +goose Up
-- JSONB rewrites object formatting and key ordering on every read.  Connector
-- snapshots are signed by their content hash, so the durable row must retain
-- the exact canonical wire bytes that the writer hashed.  Existing JSONB rows
-- are first converted to the connector protocol's deterministic compact JSON
-- bytes and their hashes are recomputed in the same transaction.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Recomputing a hash is part of this representation migration.  The v1
-- trigger intentionally rejects content-hash changes during ordinary writes,
-- so suspend it only inside this atomic migration and restore it below.
DROP TRIGGER IF EXISTS tunnel_config_generations_immutable ON tunnel_config_generations;
ALTER TABLE tunnel_config_generations
  DROP CONSTRAINT IF EXISTS tunnel_config_generations_snapshot_check;

-- jsonb::text is deterministic for PostgreSQL, but it is not the canonical
-- compact JSON used by connectorprotocol (object keys are ordered differently
-- and whitespace is inserted). Build the same compact, lexicographically
-- ordered representation that encoding/json produces for the safe snapshot
-- object before converting it to bytes. In particular, encoding/json HTML
-- escapes <, >, &, U+2028 and U+2029 even though PostgreSQL's JSON output does
-- not. Keep this scalar helper in sync with connectorprotocol.canonicalJSON.
-- +goose StatementBegin
CREATE FUNCTION canonical_config_snapshot_string(value text)
RETURNS text
LANGUAGE sql IMMUTABLE STRICT AS $$
SELECT replace(
  replace(
    replace(
      replace(
        replace(to_json(value)::text, chr(60), chr(92) || 'u003c'),
        chr(62), chr(92) || 'u003e'),
      chr(38), chr(92) || 'u0026'),
    chr(8232), chr(92) || 'u2028'),
  chr(8233), chr(92) || 'u2029')
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION canonical_config_snapshot_jsonb(value jsonb)
RETURNS text
LANGUAGE sql IMMUTABLE STRICT AS $$
SELECT CASE jsonb_typeof(value)
  WHEN 'object' THEN
    '{' || COALESCE((
      SELECT string_agg(canonical_config_snapshot_string(entry.key) || ':' || canonical_config_snapshot_jsonb(entry.value), ',' ORDER BY entry.key COLLATE "C")
      FROM jsonb_each(value) AS entry(key, value)
    ), '') || '}'
  WHEN 'array' THEN
    '[' || COALESCE((
      SELECT string_agg(canonical_config_snapshot_jsonb(entry.value), ',' ORDER BY entry.ordinality)
      FROM jsonb_array_elements(value) WITH ORDINALITY AS entry(value, ordinality)
    ), '') || ']'
  WHEN 'string' THEN canonical_config_snapshot_string(value #>> '{}')
  ELSE value::text
END
$$;
-- +goose StatementEnd

-- The old content hash is the only durable evidence of the bytes that were
-- hashed before JSONB discarded their formatting. Refuse the migration if our
-- SQL canonicalizer cannot reproduce that evidence for any row. This makes a
-- future schema/value change fail closed instead of silently issuing a
-- snapshot that SQLControlStore would reject.
-- +goose StatementBegin
DO $$
DECLARE
  row_record RECORD;
  canonical bytea;
BEGIN
  FOR row_record IN
    SELECT tunnel_id, generation, content_hash, snapshot
    FROM tunnel_config_generations
  LOOP
    canonical := convert_to(canonical_config_snapshot_jsonb(row_record.snapshot), 'UTF8');
    IF row_record.content_hash IS DISTINCT FROM digest(canonical, 'sha256') THEN
      RAISE EXCEPTION 'cannot preserve tunnel config snapshot %/%: SQL canonical bytes do not match stored content hash', row_record.tunnel_id, row_record.generation;
    END IF;
  END LOOP;
END
$$;
-- +goose StatementEnd

ALTER TABLE tunnel_config_generations
  ALTER COLUMN snapshot TYPE bytea
  USING convert_to(canonical_config_snapshot_jsonb(snapshot), 'UTF8');

UPDATE tunnel_config_generations
SET content_hash = digest(snapshot, 'sha256');

DROP FUNCTION canonical_config_snapshot_jsonb(jsonb);
DROP FUNCTION canonical_config_snapshot_string(text);

ALTER TABLE tunnel_config_generations
  ADD CONSTRAINT tunnel_config_generations_snapshot_bytes_check
    CHECK (octet_length(snapshot) > 0);

CREATE TRIGGER tunnel_config_generations_immutable
  BEFORE UPDATE ON tunnel_config_generations
  FOR EACH ROW EXECUTE FUNCTION reject_tunnel_config_identity_mutation();

-- +goose Down
-- Do not silently discard a snapshot that cannot be represented as JSONB.  A
-- future writer or manual repair must make the invariant explicit before a
-- rollback is attempted.
-- +goose StatementBegin
DO $$
DECLARE
  row_record RECORD;
  parsed jsonb;
BEGIN
  FOR row_record IN
    SELECT tunnel_id, generation, snapshot
    FROM tunnel_config_generations
  LOOP
    BEGIN
      parsed := convert_from(row_record.snapshot, 'UTF8')::jsonb;
    EXCEPTION WHEN others THEN
      RAISE EXCEPTION 'cannot roll back tunnel config snapshot %/%: payload is not valid UTF-8 JSON', row_record.tunnel_id, row_record.generation;
    END;
    IF jsonb_typeof(parsed) <> 'object' THEN
      RAISE EXCEPTION 'cannot roll back tunnel config snapshot %/%: payload is not a JSON object', row_record.tunnel_id, row_record.generation;
    END IF;
  END LOOP;
END
$$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS tunnel_config_generations_immutable ON tunnel_config_generations;

ALTER TABLE tunnel_config_generations
  DROP CONSTRAINT IF EXISTS tunnel_config_generations_snapshot_bytes_check;

-- Recreate the canonicalizer for the reverse representation conversion. The
-- post-conversion hash must describe the same compact bytes that a fresh
-- application write would produce after JSON canonicalization.
-- +goose StatementBegin
CREATE FUNCTION canonical_config_snapshot_string(value text)
RETURNS text
LANGUAGE sql IMMUTABLE STRICT AS $$
SELECT replace(
  replace(
    replace(
      replace(
        replace(to_json(value)::text, chr(60), chr(92) || 'u003c'),
        chr(62), chr(92) || 'u003e'),
      chr(38), chr(92) || 'u0026'),
    chr(8232), chr(92) || 'u2028'),
  chr(8233), chr(92) || 'u2029')
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION canonical_config_snapshot_jsonb(value jsonb)
RETURNS text
LANGUAGE sql IMMUTABLE STRICT AS $$
SELECT CASE jsonb_typeof(value)
  WHEN 'object' THEN
    '{' || COALESCE((
      SELECT string_agg(canonical_config_snapshot_string(entry.key) || ':' || canonical_config_snapshot_jsonb(entry.value), ',' ORDER BY entry.key COLLATE "C")
      FROM jsonb_each(value) AS entry(key, value)
    ), '') || '}'
  WHEN 'array' THEN
    '[' || COALESCE((
      SELECT string_agg(canonical_config_snapshot_jsonb(entry.value), ',' ORDER BY entry.ordinality)
      FROM jsonb_array_elements(value) WITH ORDINALITY AS entry(value, ordinality)
    ), '') || ']'
  WHEN 'string' THEN canonical_config_snapshot_string(value #>> '{}')
  ELSE value::text
END
$$;
-- +goose StatementEnd

ALTER TABLE tunnel_config_generations
  ALTER COLUMN snapshot TYPE jsonb
  USING convert_from(snapshot, 'UTF8')::jsonb;

ALTER TABLE tunnel_config_generations
  ADD CONSTRAINT tunnel_config_generations_snapshot_check
    CHECK (jsonb_typeof(snapshot) = 'object');

UPDATE tunnel_config_generations
SET content_hash = digest(convert_to(canonical_config_snapshot_jsonb(snapshot), 'UTF8'), 'sha256');

DROP FUNCTION canonical_config_snapshot_jsonb(jsonb);
DROP FUNCTION canonical_config_snapshot_string(text);

CREATE TRIGGER tunnel_config_generations_immutable
  BEFORE UPDATE ON tunnel_config_generations
  FOR EACH ROW EXECUTE FUNCTION reject_tunnel_config_identity_mutation();
