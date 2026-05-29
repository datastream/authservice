## Why

The authservice codebase has accumulated quality issues across all packages: duplicated boilerplate, inconsistent error handling and response formats, dead code, missing documentation, and near-zero test coverage. These issues increase maintenance burden, reduce confidence in changes, and make onboarding harder. This change consolidates common patterns, removes dead code, and adds documentation without changing external behavior.

## What Changes

- **Extract `requireLogin` helper** — replace duplicated session-start + user-lookup boilerplate across `tokens.go`, `register.go`, `oauth.go`, and `login.go` with a single `requireLogin(c *gin.Context)` helper in `middleware/session_helper.go`.
- **Use `ServeStaticHTML` everywhere** — replace inline file-serving code in `tokens.go`, `register.go`, `login.go` with the existing `middleware.ServeStaticHTML` function.
- **Consolidate FGA middleware** — merge `FGAMiddleware` and `FGASepMiddleware` into a single `permissionMiddleware` with a `relation` parameter.
- **Standardize response formats** — replace hardcoded `200` status codes with `http.StatusOK`, use consistent `"error"` key for all errors, fix `"Status"` to `"error"`.
- **Remove dead code** — remove the unused `decrypt` function, redundant `TOKEN`/`COOKIE` constants, and no-op RedisDB defaults.
- **Fix context usage** — replace `context.TODO()` and `context.Background()` in handlers with proper request-scoped contexts.
- **Add package-level documentation** — add doc comments for `controllers`, `middleware`, `models`, and `core` packages.
- **Fix typo** — `verison` → `version` in `main.go`.

## Capabilities

### New Capabilities

- `session-helpers` — shared `requireLogin` middleware helper for login-check-and-redirect
- `response-standards` — standardized HTTP status codes, error response keys, and response wrapping

### Modified Capabilities

<!-- No existing spec-level capabilities exist in openspec/specs/ yet. All changes are new capabilities. -->

## Impact

| Area | Impact |
|------|--------|
| `pkg/controllers/tokens.go` | Uses `requireLogin`, `ServeStaticHTML`; removes duplication |
| `pkg/controllers/register.go` | Uses `requireLogin`, `ServeStaticHTML`; removes duplication |
| `pkg/controllers/oauth.go` | Uses `requireLogin`; removes duplication |
| `pkg/controllers/login.go` | Uses `requireLogin`; removes `decrypt`, `TOKEN`/`COOKIE` constants |
| `pkg/controllers/fga.go` | Merges `FGAMiddleware` + `FGASepMiddleware`; fixes status codes |
| `pkg/middleware/session_helper.go` | Adds `requireLogin`, package-level doc |
| `cmd/oauthservice/main.go` | Fixes `verison` typo |
| `pkg/core/service.go` | Removes no-op RedisDB defaults, adds package-level doc |
| All controllers | Fix `context.TODO()` → `c.Request.Context()` |
| `pkg/models/*.go` | Add package-level doc comments |

No API behavior changes. All modifications are internal refactors.
