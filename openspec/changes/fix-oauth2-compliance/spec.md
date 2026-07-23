# OAuth 2.0 Compliance Specifications

## Requirements

### REQ-1: /oauth/authorize MUST return redirect-based errors (RFC 6749 §4.1.2.1)

When the authorization endpoint rejects a request (unauthenticated user, library error), it MUST respond with a 302 redirect containing the error in the query string. The `OAuthHandler` MUST NOT return JSON error bodies for authorization endpoint errors.

**Correct pattern:**
```go
// When not authenticated
c.Redirect(http.StatusFound, "/login?"+c.Request.URL.RawQuery)
```

**Not allowed:**
```go
// This produces JSON — violates RFC 6749
c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
```

### REQ-2: Password grant_type MUST NOT be supported

The authorization server MUST NOT support `grant_type=password` (RFC 6749 §4.3 deprecation, OIDC Core §5.1 prohibition). If a client sends `grant_type=password` to `/oauth/token`, the server MUST respond with `unsupported_grant_type`.

**Acceptance Criteria:**
- [ ] `SetPasswordAuthorizationHandler` is NOT called in `service.go`
- [ ] POST `/oauth/token` with `grant_type=password` returns `{"error": "unsupported_grant_type"}` with HTTP 400

### REQ-3: Token endpoint MUST emit RFC 6749 §5.2 errors

The `internalErrorHandler` MUST return a proper `*errors.Response` (never `nil`) so the library propagates error codes. Use `errors.StatusCodes` map to look up the HTTP status code and `errors.NewResponse(err, statusCode)` to construct the response.

**Acceptance Criteria:**
- [ ] `SetInternalErrorHandler` returns `*errors.Response` (not `nil`)
- [ ] Invalid token requests produce `error` parameter in JSON response

### REQ-4: Well-known metadata MUST be accurate

The `/.well-known/openid-configuration` endpoint MUST only advertise capabilities the server actually implements.

**Required fields:**
- `issuer` — required
- `authorization_endpoint` — required
- `token_endpoint` — required
- `scopes_supported` — only `["profile", "email"]` (NO `openid` — no ID tokens)
- `response_types_supported` — only `["code"]`
- `response_modes_supported` — `["query", "fragment"]`
- `claims_supported` — `["sub", "name", "email", "email_verified"]`
- `subject_types_supported` — `["public"]`
- `token_endpoint_auth_methods_supported` — `["client_secret_post", "basic"]`

**Acceptance Criteria:**
- [ ] `openid` NOT in `scopes_supported`
- [ ] `response_modes_supported` present
- [ ] `claims_supported` present
- [ ] All advertised scopes are actually handled by the server

### REQ-5: /userinfo `sub` claim MUST be a stable identifier (OIDC §4.1.1.1)

The `sub` claim in the userinfo response MUST be a stable, issuer-scoped identifier. It MUST NOT be the username (which is mutable).

**Required pattern:**
```go
// sub = numeric user ID (stable)
claims["sub"] = fmt.Sprintf("%d", user.ID)
```

**Acceptance Criteria:**
- [ ] `sub` in userinfo response is a numeric string (e.g., `"1"`, `"2"`)
- [ ] `sub` does NOT change if the username changes