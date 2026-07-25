-- name: GetUserByUsername :one
SELECT id, username, hashed_password, email, created_at, updated_at, deleted_at
FROM users
WHERE username = $1;

-- name: CreateUser :one
INSERT INTO users (username, hashed_password, email, created_at, updated_at)
VALUES ($1, $2, $3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
RETURNING id;

-- name: GetUserByID :one
SELECT id, username, hashed_password, email, created_at, updated_at, deleted_at
FROM users
WHERE id = $1;