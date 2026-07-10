## Context

This OAuth 2.0 authorization code server (go-oauth2/oauth2/v4 library, Gin framework) currently supports a browser-based auth flow with session cookies and a Vue SPA frontend. A mobile app wants to authenticate users through this server.

The server already implements:
- Authorization code flow with mandatory PKCE
- UserInfo endpoint with OpenID scopes (openid, profile, email)
- Token revocation (RFC 7678)
- Token introspection (RFC 7662)
- OpenID Connect discovery metadata
- Client registration via authenticated API
- Public/private client distinction via `Token.Public` flag

The server is missing or unclear on:
- Mobile app login flow (currently cookie/session-based with redirects)
- Refresh token support (not explicitly configured)
- Public client enforcement at token endpoint
- Custom redirect URI scheme support (`myapp://`)
- Device Authorization Grant (RFC 8628)

## Goals / Non-Goals

**Goals:**
- Audit every OAuth 2.0 / OpenID Connect endpoint for mobile app compatibility
- Identify specific gaps between current implementation and mobile requirements
- Produce a spec that can guide a follow-up implementation change

**Non-Goals:**
- Implementing mobile-specific features in this change (assessment only)
- Building a mobile app or SDK
- Device Authorization Grant implementation
- Native mobile UI or deep-linking implementation

## Decisions

### Decision 1: Assessment Approach
**Choice**: Audit each endpoint against RFC 6749 (OAuth 2.0) and RFC 7662/7678 (introspection/revocation) requirements, cross-referenced with mobile app auth patterns.

**Rationale**: The server already implements significant OAuth 2.0 functionality. Rather than re-specifying everything, we audit what exists and flag gaps. This is efficient and focused.

### Decision 2: Focus on Authorization Code + PKCE
**Choice**: The mobile app must use the existing authorization code flow with PKCE (already mandatory). No implicit flow, no password grant, no client credentials.

**Rationale**: RFC 6749 §4.1.1 and OIDC Core 3.1 explicitly require PKCE for public clients. The server already enforces this (`ForcePKCE = true`), which is correct for mobile apps.

### Decision 3: Login Flow Gap Assessment
**Choice**: The login flow uses server-side sessions with cookie-based auth. For mobile apps, there are two possible approaches:
1. **WebView-based**: Embed a WebView, navigate to `/oauth/authorize`, handle the full browser redirect flow, extract the code from the redirect URI.
2. **API-based**: Use `/api/login` for credential submission + cookie management, then navigate to `/oauth/authorize` with session cookie.

**Gap**: Neither approach is well-documented or tested for mobile apps. The redirect URI handling needs to support custom schemes for approach 1.

### Decision 4: Client Authentication Assessment
**Choice**: The server supports both Basic Auth and form-based client credentials (`r.BasicAuth` or `ClientFormHandler`). For public clients (mobile apps), only `client_id` should be required.

**Gap**: Need to verify whether the `Token.Public` flag affects token endpoint behavior. If not enforced, mobile apps would need to send `client_secret` which is insecure.

## Risks / Trade-offs

### Risk 1: Cookie-based login breaks mobile apps
Mobile apps cannot use browser cookies natively. The current login flow relies on `Set-Cookie` headers and session cookies.

→ **Mitigation**: WebView-based auth flow handles cookies transparently. For API-based auth, the `/api/login` endpoint + cookie jar management works but is not idiomatic for mobile.

### Risk 2: Redirect URI validation may reject custom schemes
If the redirect URI validator only accepts `http://` or `https://` schemes, mobile apps using `myapp://callback` will fail.

→ **Mitigation**: Audit the redirect URI validation logic in the go-oauth2 library integration. May need custom URI validation.

### Risk 3: Redirect URI whitelist may block mobile apps
Clients register redirect URIs at creation time. If the validation is too strict, mobile apps cannot register scheme-based URIs.

→ **Mitigation**: Ensure the `redirect_uri` stored in the `Token` model accepts custom schemes.

### Risk 4: Refresh tokens unclear
The server sets `SetAllowedResponseType(oauth2.Code)` which controls the authorization response, not token grant types. Whether `refresh_token` grant works depends on the go-oauth2 library defaults.

→ **Mitigation**: Test the token endpoint with `grant_type=refresh_token` to determine if it works. If not, assess whether it's needed for the mobile app.

## Migration Plan

This is an assessment-only change. No migration is needed.

If gaps are found, a follow-up `openspec` change will be created to implement the required fixes.

## Open Questions

1. Does `go-oauth2/oauth2/v4` support refresh token grant out of the box?
2. Is the `Token.Public` flag enforced at the token endpoint?
3. Does redirect URI validation accept custom schemes (`myapp://`)?
4. Can the server be configured to accept `*` or multiple origins for CORS (needed for WebView-based mobile apps)?
5. Should the server add Device Authorization Grant (RFC 8628) for desktop/TV app support?
