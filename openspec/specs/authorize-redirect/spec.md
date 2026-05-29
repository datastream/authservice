# Authorize Error Responses

## Requirements

### REQ-1: POST to /oauth/authorize when not authenticated MUST return OAuth error redirect

When the user is not authenticated and sends a POST to `/oauth/authorize`, the server MUST respond with a 302 redirect containing OAuth error parameters per RFC 6749 §4.1.2.1.

**Current (wrong):**
```go
// Returns 302 to /login — drops POST body, causes browser to GET /login
c.Header("Location", "/login")
c.JSON(http.StatusFound, gin.H{...})
```

**Required:**
```go
c.Redirect(http.StatusFound, "/login?"+c.Request.URL.RawQuery)
```

This preserves the original `client_id`, `redirect_uri`, `response_type`, and `state` values so the user can reach the consent page after logging in.

### REQ-2: GET /oauth/authorize when not authenticated MUST redirect to login with params

GET requests are already handled correctly by `AuthPage` — they redirect with preserved query params. This MUST continue to work.

### REQ-3: Authorization errors MUST include error parameter

Per RFC 6749 §4.1.2.1, authorization errors MUST include:
- `error` — Single ASCII error code (e.g., `login_required`, `access_denied`, `invalid_request`)
- `state` — The original state value if present in the request
- `error_description` — Human-readable ASCII text providing additional information (optional)
- `error_uri` — URI for more information (optional)

## Acceptance Criteria

- [ ] POST to `/oauth/authorize` when not logged in redirects to `/login?client_id=...&redirect_uri=...&response_type=...&state=...`
- [ ] Browser does NOT perform POST→GET redirect on login
- [ ] The state value is preserved in the redirect URL so the user can return to consent after login
