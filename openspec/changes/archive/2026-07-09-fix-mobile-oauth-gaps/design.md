## Context

The mobile OAuth 2.0 audit identified six gaps blocking mobile authentication. All HTML templates were moved to the Vue SPA during the Vue SPA migration. The Go backend no longer serves HTML pages.

Key gaps:
1. **Consent page broken**: `AuthPage` GET calls `template.ParseFiles("static/auth.html")` which fails. All HTML is in the Vue SPA.
2. **No redirect URI storage**: Token model has no redirect URI field. Domain field used as baseURI but is not a valid URI.
3. **Redirect URI validation**: Custom validator does host comparison, rejects custom URI schemes.
4. **Introspection returns 401**: `/test` route uses OAuthMiddleware. RFC 7662 requires 200 + `{"active": false}`.
5. **OIDC metadata wrong**: Lists `"code token"` but server only allows `oauth2.Code`.
6. **CORS preflight broken**: `r.NoRoute()` catches OPTIONS, returning SPA HTML.

## Goals / Non-Goals

**Goals:**
- Redirect OAuth authorize flow to Vue SPA consent page
- Add redirect URI storage and custom scheme validation
- Fix introspection to return RFC 7662 compliant responses
- Fix OIDC metadata accuracy
- Fix CORS preflight for OPTIONS requests
- Add JSON API endpoint for programmatic consent approval

**Non-Goals:**
- Building the Vue SPA consent page (frontend task)
- Adding Device Authorization Grant (RFC 8628)
- Changing the session/authentication architecture
- Adding new OAuth grant types

## Decisions

### Decision 1: SPA-Based Consent Flow
**Choice**: Modify `AuthPage` to redirect to Vue SPA consent route (`/consent`) on GET instead of rendering HTML. Create `POST /oauth/authorize/approve` — a JSON API endpoint that accepts the authorization parameters, generates the code via go-oauth2 library, and returns a redirect response to the client's redirect URI.

**Flow:**
1. GET `/oauth/authorize?client_id=X&redirect_uri=Y&state=Z&...` → `AuthPage`
2. AuthPage checks session → if logged in, redirect to `/consent?client_id=X&redirect_uri=Y&state=Z&...`
3. Vue SPA renders consent UI
4. User approves → Vue SPA calls `POST /oauth/authorize/approve` with auth params
5. Server generates auth code via go-oauth2 library
6. Server redirects to `redirect_uri?code=CODE&state=Z`

**Alternative considered**: Keep the existing POST `/oauth/authorize` handler but replace the template rendering with a redirect to SPA. The POST handler already delegates to the library.

**Decision rationale**: Adding a dedicated `/approve` endpoint separates the SPA/mobile flow from the legacy library flow. The POST `/oauth/authorize` can be deprecated. The `/approve` endpoint provides a clean API for both Vue SPA and mobile apps.

### Decision 2: Redirect URI Storage
**Choice**: Add `RedirectURIs string` field to `Token` model. This stores a semicolon-separated list of redirect URIs per client. On client creation, the redirect URI is stored here. When validating, the server looks up the client's registered URIs and checks if the request URI matches.

**Rationale**: The go-oauth2 library's `GenerateAuthToken` calls `m.validateURI(cli.GetDomain(), tgr.RedirectURI)`. The library passes `cli.GetDomain()` as baseURI. We cannot change this from outside the library. So:
- The validator receives baseURI (which is `Token.Domain`, e.g., `mobile-app`)
- The validator ignores the baseURI and instead looks up redirect URIs from the Token model
- If the redirect URI matches a registered URI → accept
- If no redirect URIs are registered → accept any (backward compatibility)

### Decision 3: Redirect URI Validation Logic
**Choice**: The custom validator looks up the client by extracting the client ID from the request context or query params, then checks the request redirect URI against the stored redirect URIs. If the client has no registered URIs, it falls back to the existing domain-based host comparison.

**Rationale**: This supports exact-match validation for clients that register URIs, while maintaining backward compatibility for clients that don't.

Actually, the validator has signature `func(baseURI, redirectURI string) error` and only receives strings. It has no access to the request or client ID.

**Revised Choice**: Since we control the `SetValidateURIHandler`, we can capture the request from the Gin context using a middleware that sets it on the request context. The validator extracts the client ID from the context and looks up the client's redirect URIs.

Simpler alternative: Store the redirect URI in the `Domain` field (for the library's baseURI) and also in `RedirectURIs`. The validator compares the request redirect URI against the stored redirect URIs in the `Token` model by looking up the client.

**Final choice**: The validator will do exact URI matching for registered URIs. If the client has no registered redirect URIs, the validator uses the domain-based host comparison (existing behavior).

### Decision 4: Introspection Fix
**Choice**: Remove `OAuthMiddleware` from `/test` route. The `TestHandler` already returns `{"active": false}` for invalid tokens.

### Decision 5: OIDC Metadata Fix
**Choice**: Change `response_types_supported` to `[]string{"code"}`.

### Decision 6: CORS Preflight Fix
**Choice**: Change `r.NoRoute()` to only catch GET requests. OPTIONS will reach the CORS middleware.

## Risks / Trade-offs

### Risk 1: JSON API consent endpoint exposes auth code via redirect
The `/approve` endpoint redirects directly to the client's redirect URI. If a mobile app calls it directly (not via Vue SPA), it could expose the auth code in the redirect.

→ Mitigation: This is the intended OAuth flow. The code is delivered to the client's registered redirect URI, not to the caller.

### Risk 2: Redirect URI validation change breaks existing clients
Existing clients have no redirect URI registered. Adding validation will break them.

→ Mitigation: If no redirect URI is registered, fall back to accepting any redirect URI.

### Risk 3: CORS change may expose API to unwanted origins
Restricting NoRoute to GET allows OPTIONS to reach CORS middleware.

→ Mitigation: CORS config already has `AllowOrigins` whitelist.

## Migration Plan

1. Deploy redirect URI storage and validation changes
2. Deploy JSON API consent endpoint
3. Deploy Vue SPA consent page (frontend task)
4. Deploy introspection, OIDC metadata, and CORS fixes (drop-in replacements)
5. Existing OAuth flows (web browser) continue to work
6. Mobile apps can register redirect URIs via new API endpoint

## Open Questions

1. Should redirect URIs support multiple URIs per client (array) or just one?
2. Should redirect URI registration require admin authentication or be available to all logged-in users?
