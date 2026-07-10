# CLI Example — authcli

A Go command-line client for the authservice. Uses session-based auth
(`POST /login` + cookie) to authenticate, then manages OAuth client
tokens via the `/api/tokens` endpoints.

## Prerequisites

- Go 1.25+
- A running authservice (with a user created)

## Building

```bash
cd examples/cli
go build -o authcli .
```

## Usage

### Login

```bash
# Authenticates via POST /login and caches the session cookie
# at ~/.authservice/creds.json
./authcli -s http://localhost:8080 login johndoe secret
```

### Show current user

```bash
./authcli -s http://localhost:8080 me
# {"email": "johndoe@example.com", "name": "johndoe", "sub": "johndoe"}
```

### List OAuth client tokens

```bash
./authcli -s http://localhost:8080 tokens list
# CLIENT_ID                              DOMAIN             PUBLIC
# ----------------------------------------------------------------------
# abc123def456                           my-app             yes
```

### Create a new OAuth client token

```bash
./authcli -s http://localhost:8080 tokens create -d "my-service"
# Created token: xxx
# Secret:        yyy
#
# Save this secret — it cannot be shown again!
```

### Revoke (delete) an OAuth client token

```bash
./authcli -s http://localhost:8080 tokens revoke <client-id>
```

## Commands

| Command | Description |
|---------|-------------|
| `login <user> <pass>` | Authenticate and cache session cookie |
| `me` | Show current user profile from `/userinfo` |
| `tokens list` | List all OAuth client tokens |
| `tokens create -d <domain>` | Create a new client token |
| `tokens revoke <client-id>` | Delete a client token |

## Credential Cache

Session cookies are cached in `~/.authservice/creds.json` (mode 0700).
Each command reuses the cached cookie automatically.