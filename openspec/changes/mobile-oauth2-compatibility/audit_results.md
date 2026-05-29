# Mobile OAuth 2.0 Compatibility Audit Results

## Compatibility Matrix

| Feature | Status | Notes |
|---|---|---|
| Authorization Code Flow | **Supported** | go-oauth2 library, POST `/oauth/authorize` |
| PKCE (Mandatory) | **Supported** | `ForcePKCE = true`, S256 enforced |
| PKCE Plain | **Not Supported** | Only S256 |
| Implicit Flow | **Not Supported** | `SetAllowedResponseType(oauth2.Code)` |
| State Parameter | **Supported** | Preserved through authorize GET, token exchange, error responses |
| Client Auth: Basic Auth | **Supported** | `r.BasicAuth` handled in `SetClientInfoHandler` |
| Client Auth: Form Body | **Supported** | `ClientFormHandler` fallback |
| Public Client Support | **Supported** | No client_secret required for token exchange |
| Refresh Token Grant | **Supported** | Tested with `grant_type=refresh_token` (both public and private) |
| Token Introspection (RFC 7662) | **Partially Supported** | Returns 401 instead of `{"active":false}` for invalid tokens |
| Token Revocation (RFC 7678) | **Supported** | Handles both access_token and refresh_token |
| UserInfo Endpoint | **Supported** | Scope-based claims (openid, profile, email) |
| OIDC Discovery | **Supported** | `/.well-known/openid-configuration` |
| OIDC Metadata Accuracy | **Bug** | Lists `"code token"` in response_types but server only allows `code` |
| Login: JSON Error Response | **Supported** | `{"error":"Invalid credentials"}` on 401 |
| Login: Redirect URL on Success | **Supported** | `{"redirect":"/oauth/authorize?..."}` |
| Login: Query Param Preservation | **Supported** | OAuth params preserved across login redirect |
| Session Cookie (Set-Cookie) | **Supported** | `go_session_id` cookie, HttpOnly+Secure |
| /api/login (JSON) | **Supported** | Returns `{"ok":true}`, sets session cookie |
| /api/me (session check) | **Supported** | Returns `{"username":"..."}` |
| /api/signup (registration) | **Supported** | Returns `{"ok":true}` |
| /api/logout | **Supported** | Returns `{"ok":true}` |
| Custom Redirect URI Scheme | **Rejected** | `myapp://callback` fails host validation |
| Redirect URI Registration | **Not Implemented** | No redirect_uri field in Token model |
| CORS Pre-flight (OPTIONS) | **Broken** | OPTIONS caught by SPA catch-all, returns HTML |
| CORS Configurable Origins | **Supported** | `origins` in config.json |
| Consent Page (auth.html) | **Broken** | Template file missing (replaced by Vue SPA) |
| Consent Page (GET /oauth/authorize) | **Broken** | Returns 500 `{"error":"Failed to load auth page"}` |

## Gap Severity Summary

### 🔴 Blocking (must fix before mobile use)

| Gap | Impact |
|---|---|
| **No redirect_uri registration** | Clients have no registered redirect URIs. The `SetValidateURIHandler` rejects any redirect URI because the base URI is empty. Mobile apps cannot complete the authorize flow. |
| **Redirect URI host comparison** | The custom validator (`SetValidateURIHandler`) compares URL hosts. `myapp://callback` has no host, so it's always rejected. Even if registered, the host comparison would fail for custom schemes. |
| **Consent page broken** | `static/auth.html` doesn't exist (Vue SPA removed it). GET `/oauth/authorize` returns 500. The consent flow is broken for new users. |

### 🟡 Warning (should fix for production)

| Gap | Impact |
|---|---|
| **Introspection returns 401 for invalid tokens** | Per RFC 7662 §2.1, `/test` should return `{"active": false}` with HTTP 200. Currently returns 401 due to `OAuthMiddleware`. |
| **OIDC metadata lists unsupported response_type** | `response_types_supported` includes `"code token"` but server only allows `oauth2.Code`. |
| **CORS preflight broken** | OPTIONS requests to API routes return SPA HTML instead of CORS response. Breaks cross-origin requests from WebViews. |
| **Cookie-based sessions** | Native mobile apps can't manage cookies. Only WebView-based flow works without changes. |

### ⚪ Non-Issue

| Feature | Status |
|---|---|
| PKCE enforcement | Works correctly for mobile public clients |
| Authorization code grant | Works correctly |
| Token endpoint (public client) | Works without client_secret |
| Refresh token grant | Supported for both public and private clients |
| State parameter | Preserved correctly |
| Token revocation | RFC 7678 compliant |
| Login JSON responses | Correct for programmatic clients |

## Recommended Mobile Auth Flow

### Option A: WebView-Based (Recommended for current server state)

```
1. App navigates user's device browser to:
   GET /oauth/authorize?
     client_id=APP_CLIENT_ID&
     redirect_uri=myapp://callback&
     response_type=code&
     code_challenge=PKCE_CHALLENGE&
     code_challenge_method=S256&
     state=STATE

2. User logs in via /login page (rendered in device browser)

3. After login, user sees consent page (currently BROKEN - needs fix)

4. User approves consent → server redirects to:
   myapp://callback?code=AUTH_CODE&state=STATE

5. App captures code from deep link

6. App exchanges code for tokens:
   POST /oauth/token
     grant_type=authorization_code&
     code=AUTH_CODE&
     code_verifier=PKCE_VERIFIER&
     client_id=APP_CLIENT_ID&
     redirect_uri=myapp://callback

7. App receives access_token, can use /userinfo and /test
```

**Prerequisite**: Steps 3 and the redirect URI validation must be fixed before this works.

### Option B: API-Based (Programmatic)

```
1. App calls POST /api/signup (if new user)
2. App calls POST /api/login with credentials
   → Returns {"ok":true}, sets session cookie
3. App manages cookie jar (resends go_session_id)
4. App calls POST /oauth/authorize with PKCE params + session cookie
   → Library processes authorization, redirects to custom scheme
5. App captures deep link from device browser
6. App exchanges code for tokens at /oauth/token
```

**Note**: Cookie management is non-idiomatic for native mobile apps. WebView is simpler.

## Implementation Recommendations (Follow-up Change)

1. **Add redirect_uri to Token model** — Store redirect URIs per client in the database
2. **Register redirect URIs with go-oauth2 library** — On client creation, register with `manager.AuthorizeClientIdSecret`
3. **Fix redirect URI validation** — Replace host comparison with scheme+host comparison for custom URI schemes
4. **Add consent page (auth.html)** — Either restore the template or create a new consent API endpoint
5. **Fix introspection endpoint** — Remove `OAuthMiddleware` from `/test`, let `TestHandler` return `{"active": false}` for invalid tokens
6. **Fix OIDC metadata** — Only advertise `code` in `response_types_supported`
7. **Fix CORS preflight** — Exclude OPTIONS from SPA catch-all or add explicit OPTIONS handlers
8. **Consider adding refresh token TTL config** — Document refresh token behavior for mobile developers

## Open Questions

1. Should the server support `offline_access` scope to explicitly indicate refresh token issuance?
2. Should redirect URI validation accept `http://localhost` and `http://127.0.0.1` for mobile development?
3. Should the server implement Device Authorization Grant (RFC 8628) for desktop/TV app support?
4. Should the consent page be replaced with an API-based consent flow (JSON response instead of HTML template)?
5. What is the refresh token TTL? Is it configurable?
6. Should the server support `com.example` bundle-id style redirect URIs (e.g., `com.myapp://callback`)?
