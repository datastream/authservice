-- name: GetAccessTokenByAccessKey :one
SELECT id, user_name, access_key, secret_key, description, created_at, updated_at, deleted_at
FROM access_tokens
WHERE access_key = ?;

-- name: GetAccessTokenByAccessKeyAndSecretKey :one
SELECT id, user_name, access_key, secret_key, description, created_at, updated_at, deleted_at
FROM access_tokens
WHERE access_key = ? AND secret_key = ?;
