-- name: GetTokenByClientID :one
SELECT id, user_id, client_id, client_secret, domain, public, describe, redirect_uris, created_at, updated_at, deleted_at
FROM tokens
WHERE client_id = ?;

-- name: GetTokenByID :one
SELECT id, user_id, client_id, client_secret, domain, public, describe, redirect_uris, created_at, updated_at, deleted_at
FROM tokens
WHERE id = ?;

-- name: CreateToken :exec
INSERT INTO tokens (user_id, client_id, client_secret, domain, public, describe, redirect_uris, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'));

-- name: DeleteToken :exec
DELETE FROM tokens
WHERE client_id = ?;

-- name: GetTokensByUserID :many
SELECT id, user_id, client_id, client_secret, domain, public, describe, redirect_uris, created_at, updated_at, deleted_at
FROM tokens
WHERE user_id = ?;

-- name: GetTokensByDomain :many
SELECT id, user_id, client_id, client_secret, domain, public, describe, redirect_uris, created_at, updated_at, deleted_at
FROM tokens
WHERE domain = ?;

-- name: UpdateRedirectURIs :exec
UPDATE tokens
SET redirect_uris = ?, updated_at = datetime('now')
WHERE client_id = ?;