# Mobile OAuth 2.0 Compatibility Assessment

## Why

A mobile app wants to use this OAuth 2.0 authorization code server for authentication. Before development can begin, we need to assess whether the current API implementation is compatible with mobile app requirements and identify any gaps that need to be addressed.

## What Changes

This change is an **audit and assessment only**. It produces:
- A detailed compatibility matrix of OAuth 2.0 / OpenID Connect features vs mobile app requirements
- Specification of any gaps found between current implementation and mobile needs
- A plan for follow-up implementation if gaps are identified

## Capabilities

### New Capabilities
- `mobile-oauth-compat`: Specification for mobile app OAuth 2.0 compatibility requirements and gap analysis

### Modified Capabilities
None yet — assessment will determine if existing specs need delta modifications.

## Impact

### Affected Code
- `pkg/controllers/oauth.go` — OAuth authorize/token/userinfo endpoints
- `pkg/controllers/login.go` — Login flow (session-based auth)
- `pkg/core/service.go` — OAuth server configuration
- `pkg/models/tokens.go` — Client model (public/private flag)
- `cmd/oauthservice/main.go` — Route registration, CORS config

### APIs Assessed
| Endpoint | Method | Mobile Relevant |
|---|---|---|
| `/oauth/authorize` | GET/POST | Authorization flow entry |
| `/oauth/token` | POST | Token exchange (PKCE) |
| `/userinfo` | GET | User profile retrieval |
| `/test` | GET | Token introspection (RFC 7662) |
| `/oauth/revoke` | POST | Token revocation (RFC 7678) |
| `/login` | POST | User authentication (session) |
| `/api/login` | POST | SPA login (JSON) |
| `/.well-known/openid-configuration` | GET | Discovery metadata |

### Configuration to Consider
- CORS origins (`config.json.origins`) — affects WebView-based mobile apps
- Session cookie name (`sessionName`) — mobile apps need to manage cookies
- Redirect URI validation — needs to support custom schemes (`myapp://`)
- Client authentication — public clients (mobile) must work without `client_secret`
