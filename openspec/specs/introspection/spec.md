# RFC 7662 Introspection

## Requirements

### REQ-1: /test endpoint MUST return RFC 7662 compliant responses

The `/test` endpoint MUST conform to RFC 7662 §2.2 when the token is active.

**Current (wrong):**
```json
{
  "client_id": "...",
  "user_id": "...",
  "expires_in": 123456,
  "scope": "..."
}
```

**Required (active=true):**
```json
{
  "active": true,
  "scope": "openid profile email",
  "client_id": "...",
  "user": "johndoe",
  "iat": 1234567290,
  "exp": 1234567890
}
```

Fields per RFC 7662 §2.2:
- `active` (REQUIRED) — Boolean, MUST be `true`
- `scope` (RECOMMENDED) — Space-delimited string of scopes
- `client_id` (REQUIRED) — Client identifier
- `user` (RECOMMENDED) — Human-readable identifier
- `iat` (RECOMMENDED) — Issued-at time (Unix timestamp)
- `exp` (RECOMMENDED) — Expiration time (Unix timestamp)

### REQ-2: /test endpoint MUST return active=false for invalid tokens

When no token or an invalid token is provided, the response MUST be:

```json
{
  "active": false
}
```

## Acceptance Criteria

- [ ] Valid bearer token returns `active: true` with `client_id`, `scope`, `iat`, `exp`
- [ ] Missing/invalid token returns `{"active": false}` with HTTP 200
- [ ] Response is always HTTP 200 (RFC 7662 §2.1: introspection endpoint returns 200 for both active and inactive)
