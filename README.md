# Auth Server

OAuth 2.0 / OpenID Connect authentication server with a Vue SPA frontend, optional OpenFGA-based authorization, and pluggable storage backends.

## Prerequisites

| Component | Version | Notes |
|-----------|---------|-------|
| Go | 1.24+ | Backend service |
| Node.js | 18+ | Only needed to build the frontend bundle |
| pnpm / npm | any | Frontend package manager |

Optional infrastructure (required for full-featured deployments):

| Component | Purpose |
|-----------|---------|
| PostgreSQL / MySQL / SQLite | User and token persistence |
| Redis 6+ | Session store and OAuth token storage (recommended for production) |
| OpenFGA | Policy-based authorization (`/api/v1/fga/*`) |

## Quick Start (development)

1. **Install dependencies**

```bash
# Backend
go mod download

# Frontend (builds into static/index.html)
cd frontend && pnpm install && pnpm build && cd ..
```

2. **Create a config file** (see [Configuration](#configuration) below)

```bash
cp config.json config.json.bak
```

3. **Run the service**

```bash
go run ./cmd/oauthservice/main.go -c config.json
```

The server listens on `:8080` by default. Open `http://localhost:8080` in your browser.

## Building for Production

### 1. Build the frontend bundle

```bash
cd frontend
pnpm install
pnpm build
cd ..
```

This generates `static/index.html` and `static/assets/` with the Vue SPA bundle.

### 2. Build the Go binary

```bash
# Basic build
go build -o authservice ./cmd/oauthservice

# Build with version injected (set via ldflags from CI/git)
LDFLAGS="-X main.VersionString=$(git rev-parse --short HEAD)" \
  go build -ldflags "$LDFLAGS" -o authservice ./cmd/oauthservice
```

### 3. Run the binary

```bash
./authservice -c config.json
```

## Configuration

The service is configured via a JSON or YAML file passed with `-c`:

```jsonc
{
  "listenAddress": ":8080",       // HTTP listen address
  "domain": "auth.example.com",   // optional, for reverse-proxy setups
  "dbFile": "./data/authserver.db",
  "databaseURI": "postgres://user:pass@host:5432/dbname",
  "databaseType": "sqlite",       // sqlite | postgresql | mysql
  "logFile": "./logs/authserver.log",
  "sessionName": "AUTH_SESSION",  // cookie name
  "origins": ["https://app.example.com"],  // CORS allowed origins
  "redis": "localhost:6379",      // optional, Redis addr (empty = file-based)
  "redisPassword": "",
  "redisDB": 0,
  "redisTokenDB": 1,
  "openFgaConfig": {
    "url": "https://your-store.auth.openfga.app",
    "storeID": "store-uuid",
    "modelID": "model-uuid",
    "token": "fga-api-token"
  }
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `listenAddress` | yes | Host and port to bind |
| `databaseType` | yes | `sqlite` (dev), `postgresql`, or `mysql` |
| `dbFile` | yes if SQLite | Path to the SQLite database file |
| `databaseURI` | yes if PG/MySQL | Full connection string |
| `logFile` | yes | Path for append-only application log |
| `sessionName` | no | Session cookie name |
| `origins` | yes | CORS allowed origins (must include your frontend URL) |
| `redis` | no | `host:port` for Redis. If empty, sessions and tokens use file-based storage |
| `openFgaConfig.*` | no | OpenFGA integration for `/api/v1/fga/*` endpoints |

> **SQLite is for development only.** Use PostgreSQL or MySQL for any multi-instance or production deployment.

## Deployment Targets

### Docker (recommended)

```dockerfile
# ---- Build frontend ----
FROM node:18-alpine AS frontend
WORKDIR /app/frontend
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile
COPY frontend/ ./
RUN pnpm build

# ---- Build backend ----
FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /app/frontend/static ./static
ARG LDFLAGS=""
RUN go build -ldflags "$LDFLAGS" -o authservice ./cmd/oauthservice

# ---- Runtime ----
FROM alpine:3.20
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=builder /app/authservice .
COPY config.json .
RUN mkdir -p data logs
EXPOSE 8080
CMD ["./authservice", "-c", "config.json"]
```

Build and run:

```bash
docker build -t authserver:latest .
docker run -p 8080:8080 -v $(pwd)/config.json:/app/config.json:ro authserver:latest
```

### systemd

```bash
# Build
go build -ldflags "-s -w" -o /usr/local/bin/authservice ./cmd/oauthservice

# Config
cp config.json /etc/authserver/config.json

# Service unit
cat <<EOF | sudo tee /etc/systemd/system/authserver.service
[Unit]
Description=Auth Server
After=network.target postgresql.service redis.service

[Service]
ExecStart=/usr/local/bin/authservice -c /etc/authserver/config.json
Restart=on-failure
User=www-data
Group=www-data
RuntimeDirectory=authserver
LogsDirectory=authserver

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now authserver
```

### Docker Compose (full stack)

```yaml
services:
  authserver:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./config.json:/app/config.json:ro
      - db-data:/app/data
      - log-data:/app/logs
    depends_on:
      - redis
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    volumes:
      - redis-data:/data
    restart: unless-stopped

volumes:
  db-data:
  log-data:
  redis-data:
```

## Health Check

```bash
curl http://localhost:8080/healthz
# {"status":"ok"}
```

## OAuth 2.0 Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/oauth/authorize` | Authorization page (consent) |
| POST | `/oauth/authorize` | Process authorization request |
| POST | `/oauth/token` | Exchange code for token |
| GET | `/oauth/revoke` | Revoke a token |
| GET | `/userinfo` | User info endpoint |
| GET | `/.well-known/openid-configuration` | OIDC discovery |

Supported grant: **Authorization Code** with **PKCE** enforcement.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/login` | User login |
| POST | `/api/signup` | User registration |
| POST | `/api/logout` | User logout |
| GET | `/api/me` | Current user profile |
| GET | `/api/tokens` | List OAuth tokens |
| POST | `/api/tokens` | Create OAuth token |
| DELETE | `/api/tokens/:id` | Revoke token |

### OpenFGA (optional)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/fga/models` | Create FGA model |
| GET | `/api/v1/fga/models/:id` | Get FGA model |
| POST | `/api/v1/fga/models/:id/evaluate` | Evaluate permission |
| POST | `/api/v1/fga/models/:id/tuples` | Create tuples |
| DELETE | `/api/v1/fga/models/:id/tuples` | Delete tuples |

## Directory Structure

```
.
├── cmd/oauthservice/main.go   # Entry point
├── pkg/
│   ├── core/                  # Config, DB init, OAuth server wiring
│   ├── controllers/           # HTTP handlers (Gin)
│   ├── middleware/             # Session, auth, error helpers
│   └── models/                # GORM models (User, Token, AccessToken)
├── static/                    # Built Vue SPA + templates
├── frontend/                  # Vue 3 + Vite source
├── config.json               # Runtime config
└── go.mod
```
