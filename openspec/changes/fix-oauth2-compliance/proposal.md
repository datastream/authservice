# Fix OAuth 2.0 Compliance Gaps

## Why

The server's OAuth 2.0 implementation has several deviations from RFC 6749, RFC 6750, RFC 7678, and OpenID Connect Core that break interoperability with standards-conformant OAuth/OIDC clients:

1. **`/oauth/authorize` returns JSON errors** instead of the required 302 redirect with error query parameters (RFC 6749 §4.1.2.1). Browser-based and mobile clients expect redirects.
2. **Password grant is enabled** — forbidden by OIDC Core §5.1 and explicitly deprecated by RFC 6749 §4.3.2 for first-party use.
3. **Well-known metadata is incomplete** — missing required OIDC fields (`scopes_supported` only lists `openid` without ID token support, `response_modes_supported` absent, `claims_supported` absent).
4. **`/userinfo` `sub` claim uses username** — username is mutable and not scoped to the issuer, violating OIDC Core §4.1.1.1 and §8.5.
5. **Token endpoint errors are suppressed** — the internal error handler returns `nil`, so the library never emits error responses.

## What Changes

### 1. Fix `/oauth/authorize` error responses (RFC 6749 §4.1.2.1)

- **`OAuthHandler` (POST)**: Remove the redundant session check (lines 136-149) that returns JSON. The library's `userAuthorizeHandler` (service.go:232-245) already handles unauthenticated users with a 302 redirect. Removing the duplicate check lets the library's redirect flow take over.
- **`AuthorizeApprove` (POST /approve)**: Already a JSON API — keep returning JSON for programmatic clients (Vue SPA, mobile). This endpoint is correctly designed for non-browser clients.

### 2. Remove password grant

- Remove `SetPasswordAuthorizationHandler` from `pkg/core/service.go`.
- Remove `passwordAuthorizationHandler` function.

### 3. Fix `/userinfo` `sub` claim

- Extract the `FindUserByUsername` call before building the claims map, then use `fmt.Sprintf("%d", user.ID)` for the `sub` value.
- Also fix `claims["name"]` to use `user.Username` instead of `token.GetUserID()`.
- Add nil guard for `user.Email` when setting `claims["email"]`.
- Per OIDC §8.5: "The sub Claim MUST be scoped to the Issuer." A numeric stable ID satisfies this.

### 4. Enrich `.well-known/openid-configuration`

- **Remove `openid`** from `scopes_supported` — we don't generate ID tokens, so `openid` scope is meaningless
- Add `response_modes_supported: ["query", "fragment"]` — the library uses `query` by default
- Add `claims_supported: ["sub", "name", "email", "email_verified"]` — based on what `/userinfo` actually returns
- Add `subject_types_supported: ["public"]` — only public subjects are supported
- Add `token_endpoint_auth_methods_supported: ["client_secret_post", "basic"]` — per RFC 6749 §2.3.1

### 5. Fix internal error handler to suppress errors gracefully

- The `SetInternalErrorHandler` currently returns `nil` on error, suppressing the error response entirely. Change it to return the error response so the library emits a proper RFC 6749 §5.2 response.

## Capabilities

### New Capabilities
- `oauth-authorize-errors`: `/oauth/authorize` MUST return RFC 6749 §4.1.2.1 compliant redirect-based errors (302 with `error` parameter in query string)
- `oauth-token-errors`: `/oauth/token` MUST return RFC 6749 §5.2 compliant error responses (no suppressed errors)

### Modified Capabilities
- `openid-metadata`: Add required OIDC metadata fields; remove `openid` from `scopes_supported` if ID tokens are not implemented
- `vue-spa-auth`: `/oauth/authorize` POST errors MUST redirect to login with preserved params
- `userinfo-claims`: `sub` claim MUST be a stable, issuer-scoped identifier (not username)

## Impact

| File | Change |
|---|---|
| `pkg/controllers/oauth.go` | Fix `OAuthHandler` error responses (redirect → JSON), fix `/userinfo` `sub` claim |
| `pkg/core/service.go` | Remove password grant handler, fix internal error handler to return error response |
| `pkg/controllers/login.go` | Enrich well-known metadata with required OIDC fields |
| `go.mod` | No new dependencies |

No schema changes, no new routes, no frontend changes.