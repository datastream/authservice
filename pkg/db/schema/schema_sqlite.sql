CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT(255) NOT NULL UNIQUE,
    hashed_password BLOB NOT NULL,
    email TEXT(255),
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    deleted_at DATETIME
);

CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT(255) NOT NULL,
    client_id TEXT(255) NOT NULL UNIQUE,
    client_secret TEXT(256) NOT NULL,
    domain TEXT(255) NOT NULL,
    public INTEGER NOT NULL DEFAULT 0,
    description TEXT,
    redirect_uris TEXT,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    deleted_at DATETIME
);

CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id);

CREATE TABLE IF NOT EXISTS access_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_name TEXT(255) NOT NULL,
    access_key TEXT(255) NOT NULL,
    secret_key TEXT(255) NOT NULL,
    description TEXT,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    deleted_at DATETIME
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_access_tokens_access_key_secret_key ON access_tokens(access_key, secret_key);
CREATE INDEX IF NOT EXISTS idx_access_tokens_user_name ON access_tokens(user_name);