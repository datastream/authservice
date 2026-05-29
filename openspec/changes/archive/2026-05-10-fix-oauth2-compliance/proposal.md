# Proposal: Fix OAuth 2.0 Compliance Issues

## Why

Our OAuth 2.0 authorization server has several RFC 6749 and RFC 7662 compliance gaps that were identified during a code review:

1. **Missing `state` parameter** — vulnerable to CSRF attacks on the authorization endpoint
2. **False OpenID Connect claims** — advertises ID Token support without delivering them
3. **POST→302 redirect on authorize** — browser sends a GET to login when POST to `/oauth/authorize` fails
4. **CORS blocks Bearer tokens** — SPA apps can't preflight requests with `Authorization` header
5. **Consent bypass on login** — password flow with `client_id` skips the consent page
6. **Introspection not RFC 7662 compliant** — `/test` endpoint returns custom response shape

## Scope

### In Scope
- Add `state` parameter support to `/oauth/authorize`
- Fix `.well-known/openid-configuration` to only advertise supported features
- Return proper OAuth error codes on authorize failures
- Add `Authorization` to CORS allow-headers
- Remove `state` bypass on POST `/login`
- Make `/test` RFC 7662 compliant

### Out of Scope
- Refresh token support (not supported by go-oauth2/v4)
- OIDC ID Token implementation (would require JWT library integration)
- Password grant deprecation (design decision, left to user)
- `/userinfo` field cleanup (cosmetic)
- JWKS endpoint implementation

## Impact
- **Security**: Fixes critical CSRF gap on authorization flow
- **Compatibility**: CORS fix enables browser-based OAuth clients
- **Correctness**: Metadata accurately reflects server capabilities
- **User safety**: Consent page no longer bypassed

## Migration Notes
- Clients relying on the non-RFC `/test` introspection endpoint will need updating
- Adding `Authorization` to CORS headers expands attack surface for credentialed requests — origins are already whitelist-controlled
