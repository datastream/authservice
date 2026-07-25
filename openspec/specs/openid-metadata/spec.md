# OpenID Metadata Accuracy

## Requirements

### REQ-1: .well-known/openid-configuration MUST only advertise supported features

The `/.well-known/openid-configuration` endpoint MUST only advertise capabilities the server actually implements. All URIs in the metadata (including `jwks_uri`) point to endpoints that return valid responses.

**Current (wrong):**
```json
"response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"]
```

**Required:**
```json
"response_types_supported": ["code", "token", "code token"]
```

### REQ-2: JWKS URI MUST not be advertised without implementation

**SATISFIED**: The `/.well-known/jwks.json` endpoint exists and returns a valid RFC 7517-compliant JWKS document. No further action needed.

### REQ-2a: /.well-known/openid-configuration MUST include jwks_uri

Per RFC 8414 Section 3, the `/.well-known/openid-configuration` endpoint MUST include a `jwks_uri` field whose value is the full URL of the JWKS endpoint (e.g., `https://example.com/.well-known/jwks.json`).

#### Scenario: JWKS URI present in discovery document

- **WHEN** a client requests GET `/.well-known/openid-configuration`
- **THEN** the response JSON contains a `jwks_uri` field with a non-empty string value

#### Scenario: JWKS URI matches actual endpoint URL

- **WHEN** the discovery document is generated
- **THEN** `jwks_uri` points to `<scheme>://<host>/.well-known/jwks.json` matching the same scheme and host derivation used for other endpoints in the metadata

#### Scenario: JWKS URI uses correct scheme

- **WHEN** the `X-Forwarded-Proto` header is set to `https`
- **THEN** `jwks_uri` uses `https://` as the scheme

### REQ-3: Scopes advertised MUST match actual scope support

The `scopes_supported` field MUST list scopes the server actually handles. Current value `["openid", "profile", "email"]` is acceptable if the OAuth library supports scope passthrough.

## Acceptance Criteria

- [ ] `response_types_supported` contains only `code`, `token`, and `code token`
- [ ] No `id_token` or `code id_token` or `token id_token` or `code token id_token` in `response_types_supported`
- [ ] `jwks_uri` field present in metadata response with a non-empty string value
- [ ] `jwks_uri` points to a valid `/.well-known/jwks.json` endpoint that returns HTTP 200 with a valid RFC 7517-compliant JWKS document
- [ ] Metadata is valid JSON and returns HTTP 200