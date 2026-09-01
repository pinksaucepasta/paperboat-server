-- name: ListUserFavorites :many
SELECT user_id, kind, resource_id, created_at FROM user_favorites
WHERE user_id = sqlc.arg(user_id) ORDER BY created_at, kind, resource_id;

-- name: LockUserForFavorites :one
SELECT id FROM users WHERE id = sqlc.arg(user_id) FOR UPDATE;

-- name: UserOwnsFavoriteResource :one
SELECT EXISTS (
  SELECT 1 FROM user_machines m0
  WHERE sqlc.arg(kind)::text = 'machine' AND m0.user_id = sqlc.arg(owner_user_id) AND m0.id = sqlc.arg(resource_id)
  UNION ALL
  SELECT 1 FROM user_machine_terminal_sessions s
  JOIN user_machines m ON m.id = s.user_machine_id
  WHERE sqlc.arg(kind)::text = 'session' AND m.user_id = sqlc.arg(owner_user_id)
    AND (m.id || ':' || s.id) = sqlc.arg(resource_id)
);

-- name: CountUserFavorites :one
SELECT count(*) FROM user_favorites WHERE user_id = sqlc.arg(user_id);

-- name: CreateUserFavorite :execrows
INSERT INTO user_favorites (user_id, kind, resource_id)
VALUES (sqlc.arg(user_id), sqlc.arg(kind), sqlc.arg(resource_id))
ON CONFLICT DO NOTHING;

-- name: DeleteUserFavorite :execrows
DELETE FROM user_favorites WHERE user_id = sqlc.arg(user_id)
AND kind = sqlc.arg(kind) AND resource_id = sqlc.arg(resource_id);
