## 1. Add RequireLogin helper to middleware

- [x] 1.1 Add `RequireLogin(c *gin.Context) string` to `pkg/middleware/session_helper.go`
- [x] 1.2 Add package-level doc comment to `pkg/middleware/session_helper.go`

## 2. Add ServeStaticHTML usage to controllers

- [x] 2.1 Replace inline file-serving in `pkg/controllers/tokens.go` with `ServeStaticHTML`
- [x] 2.2 Replace inline file-serving in `pkg/controllers/register.go` with `ServeStaticHTML`
- [x] 2.3 Replace inline file-serving in `pkg/controllers/login.go` with `ServeStaticHTML`

## 3. Replace session boilerplate with RequireLogin

- [x] 3.1 Update `pkg/controllers/tokens.go` handlers to use `RequireLogin`
- [x] 3.2 Update `pkg/controllers/register.go` to use `RequireLogin`
- [x] 3.3 Update `pkg/controllers/oauth.go` to use `RequireLogin`
- [x] 3.4 Update `pkg/controllers/login.go` handlers to use `RequireLogin`

## 4. Consolidate FGA middleware

- [x] 4.1 Merge `FGAMiddleware` and `FGASepMiddleware` into a single `PermissionMiddleware` factory in `pkg/controllers/fga.go`
- [x] 4.2 Update route registrations in `main.go` to use the new `PermissionMiddleware` factory (not needed - deprecated wrappers are pass-throughs)

## 5. Standardize response formats

- [x] 5.1 Replace bare `200` with `http.StatusOK` in `pkg/controllers/fga.go`
- [x] 5.2 Replace bare `200` with `http.StatusOK` in `pkg/controllers/main.go` (if applicable)
- [x] 5.3 Replace `"Status"` key with `"error"` in `pkg/controllers/login.go`

## 6. Remove dead code

- [x] 6.1 Remove unused `decrypt` function from `pkg/controllers/login.go`
- [x] 6.2 Remove redundant `TOKEN`/`COOKIE` constants from `pkg/controllers/login.go`
- [x] 6.3 Remove no-op `RedisDB == 0` defaults from `pkg/core/service.go`

## 7. Fix context usage

- [x] 7.1 Replace `context.TODO()` with `c.Request.Context()` in `pkg/controllers/tokens.go`
- [x] 7.2 Replace `context.Background()` with `c.Request.Context()` in `pkg/controllers/fga.go`

## 8. Add package-level documentation

- [x] 8.1 Add package-level doc comment to `pkg/controllers` package
- [x] 8.2 Add package-level doc comment to `pkg/models` package
- [x] 8.3 Add package-level doc comment to `pkg/core` package (already present)
- [x] 8.4 Fix `Register` doc comment in `pkg/models/common.go` (currently describes wrong behavior)

## 9. Fix typo

- [x] 9.1 Fix `verison` → `version` in `cmd/oauthservice/main.go`
