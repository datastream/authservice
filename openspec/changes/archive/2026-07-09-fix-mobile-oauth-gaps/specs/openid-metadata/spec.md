## MODIFIED Requirements

### REQ-1: .well-known/openid-configuration MUST only advertise supported features

The `/.well-known/openid-configuration` endpoint MUST only advertise capabilities the server actually implements.

**Current (wrong):**
```json
"response_types_supported": ["code", "code token"]
```

**Required:**
```json
"response_types_supported": ["code"]
```

The server only supports the `authorization_code` response type (configured via `SetAllowedResponseType(oauth2.Code)`). The `"code token"` entry MUST be removed as it is not actually supported.

## Acceptance Criteria

- [ ] `response_types_supported` contains only `["code"]`
- [ ] No `token`, `id_token`, `code token`, etc. in `response_types_supported`
- [ ] Metadata is valid JSON and returns HTTP 200
