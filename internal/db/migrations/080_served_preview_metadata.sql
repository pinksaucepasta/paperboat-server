-- +goose Up
ALTER TABLE control_previews
  ADD COLUMN source_kind text NOT NULL DEFAULT 'application'
    CHECK (source_kind IN ('application','file','directory')),
  ADD COLUMN owner_mode text NOT NULL DEFAULT 'runtime'
    CHECK (owner_mode IN ('runtime','foreground','detached'));

-- +goose Down
ALTER TABLE control_previews
  DROP COLUMN IF EXISTS owner_mode,
  DROP COLUMN IF EXISTS source_kind;
