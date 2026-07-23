-- name: GetUserByUsername :one
SELECT id, username, hashed_password, email, created_at, updated_at, deleted_at
FROM users
WHERE username = ?;

-- name: CreateUser :exec
INSERT INTO users (username, hashed_password, email, created_at, updated_at)
VALUES (?, ?, ?, datetime('now'), datetime('now'));

-- name: GetUserByID :one
SELECT id, username, hashed_password, email, created_at, updated_at, deleted_at
FROM users
WHERE id = ?;