-- +goose Up
CREATE TABLE user_favorites (
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind text NOT NULL CHECK (kind IN ('machine', 'session', 'preview')),
  resource_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, kind, resource_id)
);
CREATE INDEX user_favorites_user_created_idx ON user_favorites (user_id, created_at, kind, resource_id);

-- +goose Down
DROP TABLE user_favorites;
