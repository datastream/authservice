CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    hashed_password BYTEA NOT NULL,
    email VARCHAR(255),
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    deleted_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tokens (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    client_id VARCHAR(255) NOT NULL UNIQUE,
    client_secret VARCHAR(256) NOT NULL,
    domain VARCHAR(255) NOT NULL,
    public INTEGER NOT NULL DEFAULT 0,
    describe TEXT,
    redirect_uris TEXT,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    deleted_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id);

CREATE TABLE IF NOT EXISTS access_tokens (
    id SERIAL PRIMARY KEY,
    user_name VARCHAR(255) NOT NULL,
    access_key VARCHAR(255) NOT NULL,
    secret_key VARCHAR(255) NOT NULL,
    describe TEXT,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    deleted_at TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_access_tokens_access_key_secret_key ON access_tokens(access_key, secret_key);
CREATE INDEX IF NOT EXISTS idx_access_tokens_user_name ON access_tokens(user_name);