# Design: OAuth 2.0 Compliance Fixes

## Changes at a Glance

```
pkg/controllers/oauth.go          — state param, consent-bypass fix, error handling
pkg/controllers/login.go          — fix .well-known/openid-configuration
pkg/middleware/static_server.go   — remove AuthPage redirect on POST
cmd/oauthservice/main.go          — add Authorization to CORS headers
```

## 1. State Parameter (Critical)

The `go-oauth2/oauth2/v4` library already supports `state`. We need to:

1. Ensure `ServerConfig` has `SetAuthorizeTokenEXTRAValue("state")` configured so the library generates and validates the state token.
2. If not already in `core/service.go`, verify the server setup passes state through.
3. The `go-oauth2` library (v4) auto-persists state when it receives the authorize request and validates it on the POST callback — we just need the flag enabled.

## 2. OpenID Metadata Fix

In `login.go:305`, remove `id_token` and all composite types containing `id_token` from `response_types_supported`. The server only supports `code` and `token` (and `code token`).

Also remove `jwks_uri` since no JWKS endpoint is implemented.

## 3. POST→302 Redirect Fix on Authorize

The `OAuthHandler` currently returns a 302 when the user isn't logged in. On a POST, this causes the browser to drop the request body. Fix: return a 302 with OAuth-compliant error parameters (`error=login_required&state=...`) per RFC 6749 §4.1.2.1.

For GET requests, the `AuthPage` handler already handles unauthenticated users correctly (redirects to `/login` with the original query string preserved).

## 4. CORS Authorization Header

In `main.go:50`, add `"Authorization"` to the `AllowHeaders` slice. This allows browsers to preflight requests that include bearer tokens.

## 5. Consent Bypass on Login

In `oauth.go:97-102`, the `Login` handler checks if `client_id` is in the query string and immediately calls `o.Srv.HandleAuthorizeRequest()`, skipping the consent page. Fix: always redirect the user to the consent page (`/oauth/authorize`) after login. The consent page displays the client info and lets the user approve/reject.

```
POST /login?client_id=xxx (credentials valid)
  └─▶ 200 OK {"message": "Login successful", "redirect": "/oauth/authorize?client_id=xxx&redirect_uri=...&response_type=...&scope=...&state=..."}
```

The user then visits the redirect URL to reach the consent page with all original OAuth params preserved in the query string.

## 6. RFC 7662 Introspection

In `oauth.go:134-146`, transform the `/test` endpoint to return RFC 7662 compliant fields:

```json
{
  "active": true,
  "scope": "openid profile email",
  "client_id": "...",
  "user": "johndoe",
  "exp": 1234567890,
  "iat": 1234567290
}
```

Per RFC 7662 §2.2, required fields when active=true are `active: true`. When active=false, only `active: false` is required.
