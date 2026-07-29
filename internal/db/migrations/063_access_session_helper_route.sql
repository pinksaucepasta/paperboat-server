-- +goose Up
ALTER TABLE access_sessions
  ADD COLUMN http_base_url text NOT NULL DEFAULT '';

UPDATE access_sessions
SET http_base_url = coalesce(
  nullif(descriptor #>> '{terminal,http_base_url}', ''),
  nullif(descriptor #>> '{upload,http_base_url}', ''),
  regexp_replace(nullif(descriptor #>> '{upload,endpoint}', ''), '/v1/files/staged-images/?$', ''),
  ''
);

ALTER TABLE access_sessions
  ADD CONSTRAINT access_sessions_helper_route_check
  CHECK (
    (helper_terminal_session_id IS NULL AND helper_file_session_id IS NULL)
    OR length(trim(http_base_url)) > 0
  );

-- +goose Down
ALTER TABLE access_sessions
  DROP CONSTRAINT access_sessions_helper_route_check;
ALTER TABLE access_sessions
  DROP COLUMN http_base_url;
