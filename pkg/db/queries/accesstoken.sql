-- name: GetAccessTokenByAccessKey :one
SELECT id, user_name, access_key, secret_key, describe, created_at, updated_at, deleted_at
FROM access_tokens
WHERE access_key = $1;

-- name: GetAccessTokenByAccessKeyAndSecretKey :one
SELECT id, user_name, access_key, secret_key, describe, created_at, updated_at, deleted_at
FROM access_tokens
WHERE access_key = $1 AND secret_key = $2;
