# Design Overview

## Project Structure
```
/authservice (module github.com/datastream/authservice)
├─ cmd/oauthservice/main.go          # Application entry point, config loading, server setup
├─ pkg/core/                         # Core service struct and initialization (DB, OAuth server)
├─ pkg/models/                       # GORM models: User, Token, AccessToken, etc.
├─ pkg/controllers/                  # HTTP handlers (Gin) for auth, token, FGA, static pages
│   ├─ login.go                      # Login page rendering
│   ├─ oauth.go                      # OAuth2 endpoints (authorize, token, userinfo, test)
│   ├─ tokens.go                     # Token CRUD: list, create, revoke
│   ├─ fga.go                        # OpenFGA integration for permission checks
│   └─ register.go                   # Placeholder registration flow
├─ pkg/middleware/                   # Reusable Gin middleware (session, error handling)
│   ├─ session_helper.go            # Helpers to fetch logged‑in user ID from session
│   ├─ error_response.go            # JSON error helpers (`middleware.Fail`)
│   └─ static_server.go             # Serves static HTML assets
├─ static/                           # HTML templates used by the login/auth pages
├─ config.json / config.yaml          # Runtime configuration (listen address, DB, Redis, FGA)
└─ testutils/                        # Test helpers for spinning up an in‑memory server
```

## API Endpoints
| Method | Path | Handler | Description |
|--------|------|---------|-------------|
| GET | `/healthz` | `HealthEndpoint` (inline) | Simple health check, returns `{"status":"ok"}` |
| GET | `/login` | `LoginPage` | Renders the login HTML page |
| POST | `/login` | `OAuthController.Login` | Authenticates a user, stores `LoggedInUserID` in session, returns JSON `{ "message": "Login successful", "redirect": "/userinfo" }` |
| GET | `/logout` | `Logout` | Clears session and redirects to login |
| GET | `/manager` | `Managerpage` | Serves a static manager page (requires login) |
| GET | `/tokens` | `TokensList` | Returns JSON list of tokens belonging to the logged‑in user |
| POST | `/tokens` | `ClientTokensCreate` | Creates a token. Request body JSON: `{ "domain": "example.com", "public": true, "describe": "desc", "userId": "optional" }`. Returns `{ "client_id": "...", "client_secret": "..." }` |
| DELETE | `/tokens/:id` | `TokenRevoke` | Revokes a token owned by the caller. Returns `{ "message": "Token revoked successfully" }` |
| GET | `/signup` | `NewUser` | Renders a registration page |
| POST | `/signup` | `Signup` | Handles user registration |
| POST | `/authentication` | `TokenAuth` | Custom HMAC‑style token authentication endpoint |
| GET | `/.well-known/openid-configuration` | `Config` | Returns OpenID configuration JSON |
| GET | `/oauth/authorize` | `AuthPage` | Shows consent page for OAuth flow |
| POST | `/oauth/authorize` | `OAuthController.OAuthHandler` | Handles OAuth authorization code grant |
| POST | `/oauth/token` | `OAuthController.TokenHandler` | Issues access tokens |
| GET | `/userinfo` | `OAuthController.Userinfo` | Returns user profile for a valid bearer token |
| GET | `/userinfo/emails` | `OAuthController.UserinfoEmails` | Returns email claims |
| GET | `/test` | `OAuthController.TestHandler` | Test endpoint used by integration tests |
| **OpenFGA** (protected by `AuthMiddleware` + `FGAMiddleware`):
| POST | `/api/v1/fga/models` | `FGAController.Models` | Create a new authorization model |
| GET | `/api/v1/fga/models/:id` | `FGAController.GetModel` | Retrieve a model |
| POST | `/api/v1/fga/models/:id/evaluate` | `FGAController.Evaluate` | Evaluate permissions |
| POST | `/api/v1/fga/models/:id/tuples` | `FGAController.Tuples` | Upsert tuples |
| DELETE | `/api/v1/fga/models/:id/tuples` | `FGAController.DeleteTuples` | Delete tuples |

## Session Management
* Uses `github.com/go-session/session/v3` backed by either a file store or Redis (if `srv.Redis` is configured).
* Session cookie name is configurable via `srv.SessionName`.
* The helper `middleware.GetLoggedInUserID` extracts the `LoggedInUserID` value from the session and is used by most protected handlers.

## Token Lifecycle
1. **Create** – `ClientTokensCreate` validates the payload, fills missing `userId` from session, saves a `models.Token` via GORM, and returns `client_id`/`client_secret`.
2. **List** – `TokensList` queries tokens belonging to the session user.
3. **Revoke** – `TokenRevoke` checks ownership, then deletes the token record.

All token endpoints require a valid session cookie; otherwise they redirect to `/login` with HTTP 302 status.

## OAuth2 Integration
* Powered by `github.com/go-oauth2/oauth2/v4`.
* `OAuthController` wraps the server (`Srv`) and implements the standard authorization code flow.
* Errors are funneled through `middleware.Fail` for consistent JSON error responses.
* Successful login now returns a JSON body with a `redirect` field instead of issuing an HTTP redirect.

## OpenFGA Integration
* Initialized in `main.go` via `controllers.NewFGAController` with configuration from `srv.OpenFgaConfig`.
* Two router groups:
  * `authorized` – applies `AuthMiddleware` (session auth) then `FGAMiddleware` for model‑wide operations.
  * `modelauth` – applies `FGASepMiddleware` allowing per‑model permission checks.

## Error Handling Strategy
* Centralised in `pkg/middleware/error_response.go`.
* `middleware.Fail(c, status, msg)` writes JSON `{ "error": msg }` with the supplied HTTP status code.
* All handlers use this helper for internal errors and authentication failures.

## Testing Approach
* `testutils` provides `LoadTestService` which spins up an in‑memory Gin router with a temporary SQLite DB.
* Integration tests (`api_test.go`) cover:
  * Health endpoint
  * Unauthenticated login page rendering
  * Full token lifecycle (create, list, revoke) using session cookies
* The tests verify both status codes and JSON payloads.

## Extensibility Points
* **Additional OAuth scopes** – Extend `OAuthController` to support custom scopes.
* **More OpenFGA models** – Add new model endpoints under the `/api/v1/fga/models/:id/*` namespace.
* **Static assets** – Place additional HTML/CSS/JS in `static/` and serve via `static_server.go`.

---
*Generated on 2026‑04‑10.*