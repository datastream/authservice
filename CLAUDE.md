# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

### 1. Plan Node Default

- Enter plan mode for ANY non-trivial task (3+ steps or architectural decisions)  
- If something goes sideways, STOP and re-plan immediately - don't keep pushing  
- Use plan mode for verification steps, not just building  
- Write detailed specs upfront to reduce ambiguity  

---

### 2. Subagent Strategy

- Use subagents liberally to keep main context window clean  
- Offload research, exploration, and parallel analysis to subagents  
- For complex problems, throw more compute at it via subagents  
- One task per subagent for focused execution  

---

### 3. Self-Improvement Loop

- After ANY correction from the user: update `tasks/lessons.md` with the pattern  
- Write rules for yourself that prevent the same mistake  
- Ruthlessly iterate on these lessons until mistake rate drops  
- Review lessons at session start for relevant project  

---

### 4. Verification Before Done

- Never mark a task complete without proving it works  
- Diff behavior between main and your changes when relevant  
- Ask yourself: "Would a staff engineer approve this?"  
- Run tests, check logs, demonstrate correctness  

---

### 5. Demand Elegance (Balanced)

- For non-trivial changes: pause and ask "is there a more elegant way?"  
- If a fix feels hacky: "Knowing everything I know now, implement the elegant solution"  
- Skip this for simple, obvious fixes - don't over-engineer  
- Challenge your own work before presenting it  

---

### 6. Autonomous Bug Fixing

- When given a bug report: just fix it. Don't ask for hand-holding  
- Point at logs, errors, failing tests - then resolve them  
- Zero context switching required from the user  
- Go fix failing CI tests without being told how  

---

## Task Management

1. **Plan First**: Write plan to `tasks/todo.md` with checkable items  
2. **Verify Plan**: Check in before starting implementation  
3. **Track Progress**: Mark items complete as you go  
4. **Explain Changes**: High-level summary at each step  
5. **Document Results**: Add review section to `tasks/todo.md`  
6. **Capture Lessons**: Update `tasks/lessons.md` after corrections  

---

## Core Principles

- **Simplicity First**: Make every change as simple as possible. Impact minimal code  
- **No Laziness**: Find root causes. No temporary fixes. Senior developer standards


## Common Development Commands

| Task | Command |
|------|---------|
| **Run the service** (default config file `config.json`) | `go run ./cmd/oauthservice/main.go -c config.json` |
| **Run the service** with a custom config file | `go run ./cmd/oauthservice/main.go -c <path/to/your/config.json>` |
| **Build a binary** (output `authservice`) | `go build -o authservice ./cmd/oauthservice` |
| **Run the built binary** | `./authservice -c config.json` |
| **Run all tests** | `go test ./...` |
| **Run a single test** (replace `pkg/path` and `TestName`) | `go test ./pkg/path -run ^TestName$` |
| **Lint / static analysis** | `go vet ./...` |
| **Check module dependencies** | `go mod tidy` |
| **Update dependencies** | `go get -u ./... && go mod tidy` |

> **Note**: The project does not include a `Makefile`; the above commands are the canonical way to build, run, and test the code.

## High‑Level Architecture

```
/authservice (module github.com/datastream/authservice)
│
├─ cmd/oauthservice/main.go          # Entry point – loads config, initializes DB & OAuth server, starts Gin HTTP server
│
├─ pkg/core/service.go               # Core service struct (AuthService) – holds configuration, DB, Redis, OpenFGA, OAuth2 server
│   ├─ LoadConfig()                 # Parses YAML/JSON config into AuthService
│   ├─ InitDB()                     # Sets up GORM (Postgres, MySQL, SQLite) and registers models
│   └─ InitOAuthServer()            # Configures go‑oauth2 manager, token store (file or Redis) and client store
│
├─ pkg/models/                      # Data models backed by GORM
│   ├─ user.go                      # `User` model, password hashing, lookup helpers
│   ├─ tokens.go                    # OAuth client `Token` model and client store implementation
│   ├─ accesstoken.go               # AWS‑style `AccessToken` used for HMAC auth
│   └─ common.go                    # DB registration helper
│
├─ pkg/controllers/                 # HTTP handlers (Gin)
│   ├─ login.go                     # Login page, cookie & token auth, session handling
│   ├─ oauth.go                     # OAuth endpoints: authorize, token, userinfo, test, middleware
│   ├─ fga.go                       # OpenFGA integration (model management, tuple ops, permission checks)
│   ├─ register.go                 # (Placeholder – not shown) registration flow
│   ├─ tokens.go                    # Token listing & creation UI endpoints
│   └─ ...                         # Additional controller files
│
├─ pkg/middleware/                 # Reusable Gin middleware
│   ├─ session_helper.go           # Helpers to get logged‑in user ID from session
│   ├─ error_response.go          # JSON error helpers
│   └─ static_server.go           # Serves static assets (e.g., `static/auth.html`)
│
├─ static/                         # HTML templates used by login/auth pages
│   └─ auth.html, login.html
│
└─ config.json / config.yaml        # Runtime configuration (listen address, DB URI, Redis, OpenFGA, CORS origins, etc.)
```

### Major Components

1. **`cmd/oauthservice/main.go`** – Parses flags, loads configuration (`AuthService`), initializes database, OAuth server, logging, CORS, and registers all HTTP routes.
2. **`pkg/core/service.go`** – Central configuration holder. It creates the GORM connection (Postgres/MySQL/SQLite), sets up token storage (file‑based or Redis), and wires the OAuth2 server (`go‑oauth2/oauth2/v4`).
3. **OAuth2 Server** – Managed by `go‑oauth2/oauth2/v4`. Client information is stored in the `Token` model (`pkg/models/tokens.go`). Password flow checks user credentials via `models.User`.
4. **Session Management** – Uses `go-session/session/v3` (file‑backed by default, optionally Redis). Session keys store `LoggedInUserID` for cookie‑based auth.
5. **Authentication Paths**
   - **`/login`** – Renders `static/login.html`, handles credential verification.
   - **`/oauth/authorize`** – Displays consent page (`static/auth.html`) and processes the OAuth authorize request.
   - **`/oauth/token`** – Issues access tokens.
   - **`/userinfo`** – Returns user profile information for a valid bearer token.
   - **`/authentication`** – Supports both custom token auth (AWS‑style HMAC) and encrypted cookie auth.
6. **OpenFGA Integration** (`pkg/controllers/fga.go`)
   - Initializes an OpenFGA client from the config.
   - Provides middleware (`FGAMiddleware`, `FGASepMiddleware`) to gate API routes based on FGA checks.
   - Endpoints for creating models, evaluating permissions, and managing tuples.
7. **Middleware**
   - **`AuthMiddleware`** – Extracts the subject from the `Authorization` header (AWS HMAC) or session cookie, populates Gin context keys `UserName` and `Subject`.
   - **`OAuthMiddleware`** – Validates bearer tokens for protected routes.
8. **Static Assets** – Simple HTML templates located in the `static/` directory; rendered via `html/template`.

### Development Tips

- **Configuration** – Most runtime behaviour (DB connection, Redis, CORS origins, OpenFGA endpoint) is driven by `config.json` (or a YAML file). Adjust it before launching the service.
- **Database Migration** – The code relies on GORM’s auto‑migration via `models.Register(db)`. Running the service will automatically create tables for `User`, `Token`, and `AccessToken`.
- **Redis Usage** – If `Redis` is set, token storage and session store switch to Redis; otherwise a file‑based token store is used (`a.DBFile`).
- **Testing** – Currently there are no test files, but you can add unit tests under `pkg/...` and run them with `go test ./...`.
- **Linting** – Use `go vet ./...` and optionally `golangci-lint` if you add it to the project.

---

*Generated by Claude Code*