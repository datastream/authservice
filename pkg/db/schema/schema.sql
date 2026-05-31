CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    hashed_password BYTEA NOT NULL,
    email VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP
);

CREATE TABLE tokens (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    client_id VARCHAR(255) NOT NULL UNIQUE,
    client_secret VARCHAR(256) NOT NULL,
    domain VARCHAR(255) NOT NULL,
    public BOOLEAN NOT NULL DEFAULT FALSE,
    describe TEXT,
    redirect_uris TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP
);

CREATE INDEX idx_tokens_user_id ON tokens(user_id);

CREATE TABLE access_tokens (
    id SERIAL PRIMARY KEY,
    user_name VARCHAR(255) NOT NULL,
    access_key VARCHAR(255) NOT NULL,
    secret_key VARCHAR(255) NOT NULL,
    describe TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP
);

CREATE UNIQUE INDEX idx_access_tokens_access_key_secret_key ON access_tokens(access_key, secret_key);
CREATE INDEX idx_access_tokens_user_name ON access_tokens(user_name);
