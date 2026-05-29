# Tasks: OAuth 2.0 Compliance Fixes

## 1. Fix CORS Headers (main.go)
- [x] Add `"Authorization"` to `AllowHeaders` in CORS config
- [x] Verify OPTIONS preflight works for auth endpoints
- File: `cmd/oauthservice/main.go:50`

## 2. Fix OpenID Metadata (login.go)
- [x] Remove `id_token`, `code id_token`, `token id_token`, `code token id_token` from `response_types_supported`
- [x] Keep only `code`, `token`, `code token`
- [x] Remove `jwks_uri` field from metadata response
- File: `pkg/controllers/login.go:248-256`

## 3. Fix State Parameter (oauth.go)
- [x] Verify `go-oauth2` server config enables state generation/validation
- [x] Ensure state is persisted across GET→POST authorize flow
- [x] Ensure state is included in error responses
- File: `pkg/controllers/oauth.go`

## 4. Fix POST→302 Redirect on Authorize (oauth.go)
- [x] Change `OAuthHandler` to redirect to `/login?<original_query>` instead of bare `/login`
- [x] Preserve `client_id`, `state`, `redirect_uri`, `response_type` in redirect URL
- File: `pkg/controllers/oauth.go`

## 5. Remove Consent Bypass on Login (oauth.go)
- [x] Remove the `if len(c.Query("client_id")) > 0 { o.Srv.HandleAuthorizeRequest() }` block
- [x] Always return redirect URL pointing to `/oauth/authorize?<original_query>` after successful login
- File: `pkg/controllers/oauth.go`

## 6. Make /test RFC 7662 Compliant (oauth.go)
- [x] Transform response to include `active` boolean field
- [x] Return `active: false` for invalid/missing tokens (HTTP 200)
- [x] Include `client_id`, `scope`, `iat`, `exp` for valid tokens
- File: `pkg/controllers/oauth.go`

## 7. Verification
- [ ] Run `go test ./...` — all tests pass (pre-existing TestLoginPage_Unauthenticated failure)
- [x] Test GET/POST `/oauth/authorize` with and without auth
- [x] Test POST `/login` with `client_id` — verify consent page redirect
- [x] Test `/test` with valid/invalid tokens — verify RFC 7662 response
- [x] Test `/.well-known/openid-configuration` — verify correct fields
- [x] Test CORS preflight with `Authorization` header
