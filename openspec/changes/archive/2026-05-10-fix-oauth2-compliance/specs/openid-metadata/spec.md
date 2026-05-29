# OpenID Metadata Accuracy

## Requirements

### REQ-1: .well-known/openid-configuration MUST only advertise supported features

The `/.well-known/openid-configuration` endpoint MUST only advertise capabilities the server actually implements.

**Current (wrong):**
```json
"response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"]
```

**Required:**
```json
"response_types_supported": ["code", "token", "code token"]
```

### REQ-2: JWKS URI MUST not be advertised without implementation

If `jwks_uri` is present in the metadata but no endpoint is implemented, the field MUST be removed from the response.

### REQ-3: Scopes advertised MUST match actual scope support

The `scopes_supported` field MUST list scopes the server actually handles. Current value `["openid", "profile", "email"]` is acceptable if the OAuth library supports scope passthrough.

## Acceptance Criteria

- [ ] `response_types_supported` contains only `code`, `token`, and `code token`
- [ ] No `id_token` or `code id_token` or `token id_token` or `code token id_token` in `response_types_supported`
- [ ] `jwks_uri` field removed from metadata response (or endpoint implemented)
- [ ] Metadata is valid JSON and returns HTTP 200
