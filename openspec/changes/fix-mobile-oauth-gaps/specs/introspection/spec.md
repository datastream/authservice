## MODIFIED Requirements

### Requirement: /test endpoint MUST return RFC 7662 compliant responses

The `/test` endpoint MUST conform to RFC 7662 §2.2 when the token is active.

**Current (wrong):**
```
- When no token or invalid token is provided, returns 401 {"error": "Invalid or missing access token"}
```

**Required:**
```json
{
  "active": false
}
```

Fields per RFC 7662 §2.2:
- `active` (REQUIRED) — Boolean, MUST be `true` for valid tokens
- `scope` (RECOMMENDED) — Space-delimited string of scopes
- `client_id` (REQUIRED) — Client identifier
- `user` (RECOMMENDED) — Human-readable identifier
- `iat` (RECOMMENDED) — Issued-at time (Unix timestamp)
- `exp` (RECOMMENDED) — Expiration time (Unix timestamp)

### Requirement: /test endpoint MUST return active=false for invalid tokens

When no token or an invalid token is provided, the response MUST be:

```json
{
  "active": false
}
```

And MUST return HTTP 200 (NOT 401).

## Acceptance Criteria

- [ ] Valid bearer token returns `active: true` with `client_id`, `scope`, `iat`, `exp`
- [ ] Missing/invalid token returns `{"active": false}` with HTTP 200 (NOT 401)
- [ ] Response is always HTTP 200 (RFC 7662 §2.1: introspection endpoint returns 200 for both active and inactive)
