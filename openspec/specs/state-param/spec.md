# State Parameter

## Requirements

### REQ-1: Authorize endpoint MUST support state parameter

The `/oauth/authorize` endpoint MUST accept and validate the `state` query parameter per RFC 6749 §4.1.1.

1. When the client sends a GET to `/oauth/authorize` with `state=<value>`, the consent page MUST persist the state value (hidden form field or query string).
2. On the POST callback to `/oauth/authorize`, the server MUST validate the `state` value matches the original request.
3. If the `state` parameter is missing or invalid, the server MUST return `error=invalid_request` per RFC 6749 §4.1.2.1.

### REQ-2: State MUST be returned to redirect_uri

The `state` value MUST be returned as-is in the authorization response to `redirect_uri` per RFC 6749 §4.1.1.

```
HTTP/1.1 302 Found
Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=abc123
```

### REQ-3: Authorization error responses MUST include state

If the authorization request fails (e.g., access denied), the error response MUST include the original `state` value per RFC 6749 §4.1.2.1.

```
Location: https://client.example.com/cb?error=access_denied&state=abc123
```

### REQ-4: State validation applies to all grant flows

State validation MUST work for all response types: `code` (authorization code), `token` (implicit), and any supported combinations.

## Acceptance Criteria

- [ ] GET `/oauth/authorize?client_id=foo&state=test123` renders consent page with state preserved
- [ ] POST `/oauth/authorize` with mismatched state returns `error=invalid_request`
- [ ] Error responses from authorize include the original state value
- [ ] Implicit flow (`response_type=token`) also validates state
