## 1. Add redirect URI storage

- [x] 1.1 Add `RedirectURIs` field (semicolon-separated) to `Token` model in `pkg/models/tokens.go`
- [x] 1.2 Run GORM auto-migration (handled on server start)

## 2. Create redirect URI management API

- [x] 2.1 Add `POST /api/tokens/redirectUris?clientID=...` handler in `pkg/controllers/tokens.go`
- [x] 2.2 Add `DELETE /api/tokens/redirectUris?clientID=...` handler for removing redirect URIs
- [x] 2.3 Add ownership verification to prevent cross-user redirect URI modification

## 3. Fix redirect URI validation

- [x] 3.1 Update `SetValidateURIHandler` in `pkg/core/service.go` to look up client redirect URIs from DB
- [x] 3.2 Validate redirect URI against registered URIs for exact match
- [x] 3.3 Fall back to domain-based host comparison when no redirect URIs are registered (backward compatibility)
- [x] 3.4 Support custom URI schemes (e.g., `myapp://localhost/callback`) via exact URI matching

## 4. Create JSON API consent endpoint

- [x] 4.1 Create `POST /oauth/authorize/approve` handler in `pkg/controllers/oauth.go`
- [x] 4.2 Handler accepts auth params (client_id, redirect_uri, response_type, state, scope, code_challenge, code_challenge_method)
- [x] 4.3 Handler generates auth code using go-oauth2 library's `HandleAuthorizeRequest` logic (reused)
- [x] 4.4 Handler returns redirect to `redirect_uri?code=CODE&state=STATE`
- [x] 4.5 Update `AuthPage` GET to redirect to Vue SPA `/consent` route instead of rendering HTML template

## 5. Fix introspection endpoint

- [x] 5.1 Remove `OAuthMiddleware` from `/test` route in `cmd/oauthservice/main.go`
- [x] 5.2 Verify `/test` returns `{"active": false}` with HTTP 200 for invalid/missing tokens

## 6. Fix OIDC metadata

- [x] 6.1 Change `response_types_supported` in `pkg/controllers/login.go` `Config()` to `[]string{"code"}`

## 7. Fix CORS preflight

- [x] 7.1 Update `r.NoRoute()` in `cmd/oauthservice/main.go` to only catch GET requests
- [x] 7.2 Verify OPTIONS requests to API routes return CORS headers (not SPA HTML)
- [x] 7.3 Verify SPA catch-all still works for unknown GET routes
