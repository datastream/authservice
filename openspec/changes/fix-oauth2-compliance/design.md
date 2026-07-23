## Context

The authorization server implements the core OAuth 2.0 authorization code flow using `go-oauth2/oauth2/v4` but has several deviations from RFC 6749 and OIDC Core 1.0 that break interoperability with standards-compliant OAuth/OIDC clients (mobile apps, Vue SPAs, third-party integrations).

The previous change `fix-mobile-oauth-gaps` addressed consent flow redirects, redirect URI storage, introspection, and CORS. This change addresses the remaining RFC-compliance gaps.

## Requirements Summary

| # | Requirement | RFC Section | Current State | Fix |
|---|---|---|---|---|
| 1 | Auth errors are redirect-based | 6749 §4.1.2.1 | JSON body on POST | Redirect with error params |
| 2 | Token endpoint error codes | 6749 §5.2 | Suppressed by nil handler | Return error response |
| 3 | Well-known metadata accuracy | OIDC §2 | Missing fields | Add required fields |
| 4 | `sub` is stable identifier | OIDC §4.1.1.1 | Uses username | Use numeric user ID |
| 5 | Password grant disabled | OIDC §5.1 | Enabled | Remove handler |
| 6 | No ID tokens advertised | OIDC §3.1.3.7 | `openid` in scopes | Remove from scopes |

## Decisions

### Decision 1: `/oauth/authorize` error responses

**Choice**: Change `OAuthHandler` (oauth.go:135-155) to detect error conditions and respond with the appropriate pattern:

- **Not authenticated** → 302 redirect to `/login?{original query params}`
- **Library error** → 302 redirect with `error=...&state=...` per RFC 6749 §4.1.2.1

The library's `HandleAuthorizeRequest` calls `userAuthorizeHandler` (service.go:232-245) which already redirects to `/login` when the session is missing. The problem is specifically in `OAuthHandler`'s own session check (oauth.go:136-149) which returns JSON. Remove the redundant session check — the library's own `userAuthorizeHandler` already handles unauthenticated users.

```
Current flow:
  POST /oauth/authorize  →  OAuthHandler session check → JSON {"error": "..."}

Fixed flow:
  POST /oauth/authorize  →  Library userAuthorizeHandler → 302 /login?params
```

**Rationale**: The library already has built-in redirect-to-login logic. Removing the duplicate check in `OAuthHandler` eliminates the JSON-vs-redirect mismatch.

### Decision 2: Token endpoint error responses

**Choice**: Fix the `internalErrorHandler` in service.go:161-164. Currently it logs the error and returns `nil`, which suppresses the error response entirely. Change it to return a proper error response:

```go
a.Server.SetInternalErrorHandler(func(err error) (re *errors.Response) {
    log.Println("Internal Error:", err.Error())
    status, ok := errors.StatusCodes[err]
    if !ok {
        status = 400
    }
    return errors.NewResponse(err, status)
})
```

**Rationale**: The `go-oauth2` library uses `errors.StatusCodes` map to map `error` values to HTTP status codes, and `errors.NewResponse(err, statusCode)` to construct the response. Returning `nil` tells the library "no error, proceed normally" — which produces invalid token responses. Returning the error response propagates proper RFC 6749 §5.2 error codes to the client.

### Decision 3: Well-known metadata enrichment

**Choice**: Enrich the well-known endpoint in `Config()` (login.go:186-204) to include all required OIDC fields:

```json
{
  "issuer": "https://example.com",
  "authorization_endpoint": "https://example.com/oauth/authorize",
  "token_endpoint": "https://example.com/oauth/token",
  "userinfo_endpoint": "https://example.com/userinfo",
  "scopes_supported": ["profile", "email"],
  "response_types_supported": ["code"],
  "response_modes_supported": ["query", "fragment"],
  "claims_supported": ["sub", "name", "email", "email_verified"]
}
```

Key changes:
- **Remove `openid` from `scopes_supported`** — we don't generate ID tokens, so the `openid` scope has no meaning here
- **Add `response_modes_supported`** — required by OIDC Core §3; we support `query` (default) and `fragment` (for native apps)
- **Add `claims_supported`** — lists claims the userinfo endpoint can return

**Rationale**: OIDC consumers use `.well-known` to discover capabilities. Advertising `openid` without ID tokens causes clients to fail. Missing required fields causes warnings.

### Decision 4: `/userinfo` `sub` claim

**Choice**: Change the `sub` value in `/userinfo` (oauth.go:175) from `token.GetUserID()` (username string) to the numeric user ID from the database:

```go
claims := map[string]any{
    "sub": fmt.Sprintf("%d", user.ID),  // stable numeric ID
}
```

**Rationale**: OIDC Core §4.1.1.1 requires `sub` to be "locally unique and never reassigned" and §8.5 says it "MUST be scoped to the Issuer." Usernames can change; the numeric ID cannot. Using the numeric ID ensures the `sub` is stable across username changes.

### Decision 5: Remove password grant

**Choice**: Remove the password grant handler from `service.go:160`:

```go
// REMOVED:
a.Server.SetPasswordAuthorizationHandler(passwordAuthorizationHandler)
```

**Rationale**: RFC 6749 §4.3 labels password grant as deprecated for first-party clients. OIDC Core §5.1 explicitly forbids it. It exposes user passwords to the client application, which defeats the purpose of OAuth as a delegation protocol. Clients should use the authorization code flow with PKCE instead.

### Decision 6: Error handling architecture

```
RFC 6749 §4.1.2.1 — Authorization Endpoint Errors:
  Location: {redirect_uri}?error={code}&state={state}

RFC 6749 §5.2 — Token Endpoint Errors:
  HTTP 400 {
    "error": "invalid_request",
    "error_description": "...",
    "error_uri": "..."
  }
```

The authorization endpoint uses HTTP redirects (browser-navigable). The token endpoint uses JSON (machine-parseable). Our fix respects this distinction.

## Risks / Trade-offs

### Risk 1: Removing password grant breaks existing clients

Some API clients may use `grant_type=password` for service-to-service authentication.

→ **Mitigation**: These clients should switch to the authorization code flow with PKCE (RFC 6749 §4.4 for native apps) or use a client credentials approach (not yet supported but can be added as `grant_type=client_credentials` in a future change).

### Risk 2: Removing `openid` from scopes breaks OIDC clients

Some clients may expect `openid` in scopes.

→ **Mitigation**: This is correct behavior. If a client requires OIDC (ID tokens), they should use a proper OIDC provider. Our server is an OAuth 2.0 server that happens to support a userinfo endpoint — it is not a full OIDC provider.

### Risk 3: Numeric `sub` may break existing clients

Clients that expect `sub` to be a username string may break.

→ **Mitigation**: This is a one-time migration. All existing clients will see their `sub` change from username to numeric ID. Document this in the release notes. Clients should treat `sub` as an opaque identifier regardless.

## Migration Plan

1. Deploy changes to `oauth.go`, `service.go`, `login.go`
2. Verify: OAuth authorization code flow still works
3. Verify: `/userinfo` returns numeric `sub`
4. Verify: Password grant returns `unsupported_grant_type` (400)
5. Verify: Well-known metadata is complete and accurate
6. Verify: Token endpoint returns proper error codes on failure
7. No database migrations needed
8. No frontend changes needed
9. No config changes needed