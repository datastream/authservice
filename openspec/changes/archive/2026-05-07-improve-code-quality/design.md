## Context

The authservice codebase (Go, Gin framework, go-oauth2) has no merged feature specs in `openspec/specs/`. All packages lack package-level documentation. Controllers contain repeated boilerplate (session start + user lookup, static HTML serving). Error handling and response formats are inconsistent across files. No tests exist for OAuth flows, middleware, or core service logic.

## Goals / Non-Goals

**Goals:**
- Extract shared helpers to eliminate 3+ instances of duplicated boilerplate per file
- Standardize HTTP status codes and error response keys across all controllers
- Merge the two nearly-identical FGA middleware functions into one parameterized function
- Add package-level doc comments to all packages
- Remove dead code (unused functions, no-op defaults, redundant constants)
- Fix context usage to use request-scoped contexts instead of `context.TODO()`

**Non-Goals:**
- Adding new features or endpoints
- Adding tests (covered by a separate change)
- Changing OAuth2 protocol compliance behavior
- Migrating template rendering to compile-at-startup (out of scope for this pass)
- Restructuring package layout or module boundaries

## Decisions

### Decision 1: Place `requireLogin` in `middleware/session_helper.go`

**Rationale:** Session helper is the existing home for session-related utilities (`LoggedInUserIDKey`, `GetLoggedInUserID`). Adding `requireLogin` keeps all session logic together. The function signature will be:

```go
func RequireLogin(c *gin.Context) string
```

Returns the user ID string. Calls `c.AbortWithStatusJSON` on failure (redirect to `/login`, 401), so callers don't need to check return values for failure — the context is already aborted.

### Decision 2: Consolidate `FGAMiddleware` and `FGASepMiddleware` into `permissionMiddleware`

**Rationale:** The two functions differ only in:
- The relation string (`relation` vs `"separate_relation"`)
- Whether the object uses a template (`object:subject` vs `object`)

The existing `permissionMiddleware` helper (line 44 of `fga.go`) already handles the FGA check logic. We simply expose a single public function with a `relation` and `templated` parameter.

```go
func PermissionMiddleware(srv *core.AuthService, object string, relation string, objectTemplate bool) func(*gin.Context)
```

**Alternatives considered:**
- Keep two functions: rejected — they differ by ~5 lines, merge saves maintenance cost.
- Use a config struct parameter: overkill for two boolean parameters.

### Decision 3: Use `http.StatusOK` everywhere, never bare `200`

**Rationale:** The rest of the codebase already uses `http.StatusOK`, `http.StatusInternalServerError`, etc. The few places using bare integers are inconsistent. Replacing them is a find-and-replace with zero behavior change.

### Decision 4: Remove `decrypt` function and `TOKEN`/`COOKIE` constants

**Rationale:** `decrypt` is never called (confirmed via grep). `TOKEN` and `COOKIE` constants are literal string wrappers that add no type safety or clarity. Using `strings.ToLower` + literal comparison is clear enough.

## Risks / Trade-offs

| Risk | Mitigation |
|------|-----------|
| `RequireLogin` changes return value expectations of callers | Update all 10+ call sites; review each to ensure 302 redirect is the correct behavior (all current instances do 302 to `/login`) |
| Merging FGA middleware changes function signatures | Both functions are exported; this is a minor breaking change for external users, but the authservice is not a library |
| Removing `decrypt` could break someone using it externally | The function is unexported (`decrypt`, not `Decrypt`) — only used within `login.go` |
| Context changes (`context.TODO()` → `c.Request.Context()`) could expose new cancellation behavior | This is the correct behavior — request cancellation should cancel session ops |

## Migration Plan

This is an in-place refactor with no data migration needed. Changes are internal only — no API behavior or external contracts change. Deploy as a single release after the change is merged.
