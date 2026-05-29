# Fix Mobile OAuth 2.0 Gaps

## Why

The mobile OAuth 2.0 compatibility audit (change `mobile-oauth2-compatibility`) identified six blocking and warning gaps that prevent mobile apps from using the authorization server. The consent page is broken (template deleted during Vue SPA migration), clients cannot register redirect URIs (so the redirect URI validator always rejects requests), the introspection endpoint violates RFC 7662, and CORS preflight requests are broken. These must be fixed before mobile authentication can work.

## What Changes

- **Consent page via Vue SPA**: Change `GET /oauth/authorize` to redirect to the Vue SPA's `/consent` route (instead of rendering a Go template). Add `POST /oauth/authorize/approve` JSON API endpoint for programmatic consent (used by mobile apps and the Vue SPA).
- **Add redirect URI support**: Add `RedirectURIs` field to `Token` model, create redirect URI management API endpoints, update redirect URI validation to support custom URI schemes (e.g., `myapp://localhost/callback`) and JSON-array-based stored URIs.
- **Fix introspection endpoint**: Remove `OAuthMiddleware` from `/test` route so it returns `{"active": false}` with HTTP 200 for invalid/missing tokens per RFC 7662.
- **Fix OIDC metadata**: Change `response_types_supported` to only advertise `"code"` (the only actually supported type).
- **Fix CORS preflight**: Make SPA catch-all (`NoRoute`) only apply to GET requests, allowing OPTIONS preflight to be handled by the CORS middleware.

## Capabilities

### New Capabilities
- `mobile-redirect-uris`: Client redirect URI management and custom scheme validation for mobile OAuth flows

### Modified Capabilities
- `introspection`: Introspection endpoint MUST return `{"active": false}` with HTTP 200 for invalid tokens per RFC 7662
- `openid-metadata`: `response_types_supported` MUST only list actually supported response types
- `vue-spa-serving`: SPA catch-all MUST NOT intercept OPTIONS preflight requests
- `vue-spa-auth`: Consent page MUST be handled via Vue SPA route, with JSON API consent endpoint for programmatic access

## Impact

- **Modified**: `pkg/models/tokens.go` — add `RedirectURIs` field
- **Modified**: `pkg/controllers/tokens.go` — add redirect URI management API
- **Modified**: `pkg/controllers/oauth.go` — add JSON API consent endpoint (`/approve`), fix introspection handler
- **Modified**: `pkg/core/service.go` — redirect URI validation logic
- **Modified**: `pkg/controllers/login.go` — fix OIDC metadata
- **Modified**: `cmd/oauthservice/main.go` — fix SPA catch-all for OPTIONS, route changes for consent
- **No Go template files added** — all HTML rendering stays in the Vue SPA
- **Config**: `config.json` — no changes needed
