# CORS Authorization Header

## Requirements

### REQ-1: CORS MUST allow Authorization header for bearer token requests

The CORS middleware MUST include `Authorization` in the `AllowHeaders` list to support preflight requests from browser-based OAuth clients.

**Current (wrong):**
```go
AllowHeaders: []string{"Origin", "Content-Length", "Content-Type"},
```

**Required:**
```go
AllowHeaders: []string{"Origin", "Content-Length", "Content-Type", "Authorization"},
```

### REQ-2: CORS credential support MUST remain unchanged

The existing `AllowCredentials: true` configuration MUST NOT change. Bearer token requests require credentials to be sent.

## Acceptance Criteria

- [ ] `preflight` OPTIONS request with `Authorization` in `Access-Control-Request-Headers` returns 204
- [ ] Bearer token requests from SPA apps to `/userinfo` and `/test` pass CORS preflight
- [ ] `Origin` is still properly validated against `srv.Origins` whitelist
