-- name: GetTokenByClientID :one
SELECT id, user_id, client_id, client_secret, domain, public, description, redirect_uris, created_at, updated_at, deleted_at
FROM tokens
WHERE client_id = $1;

-- name: GetTokenByID :one
SELECT id, user_id, client_id, client_secret, domain, public, description, redirect_uris, created_at, updated_at, deleted_at
FROM tokens
WHERE id = $1;

-- name: CreateToken :one
INSERT INTO tokens (user_id, client_id, client_secret, domain, public, description, redirect_uris, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
RETURNING id;

-- name: DeleteToken :exec
DELETE FROM tokens
WHERE client_id = $1;

-- name: GetTokensByUserID :many
SELECT id, user_id, client_id, client_secret, domain, public, description, redirect_uris, created_at, updated_at, deleted_at
FROM tokens
WHERE user_id = $1;

-- name: GetTokensByDomain :many
SELECT id, user_id, client_id, client_secret, domain, public, description, redirect_uris, created_at, updated_at, deleted_at
FROM tokens
WHERE domain = $1;

-- name: UpdateRedirectURIs :exec
UPDATE tokens
SET redirect_uris = $1, updated_at = CURRENT_TIMESTAMP
WHERE client_id = $2;