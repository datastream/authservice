## 1. Audit Authorization Code Flow

- [x] 1.1 Verify authorize endpoint accepts PKCE S256 code_challenge and code_challenge_method
- [x] 1.2 Verify authorize endpoint rejects requests without PKCE parameters
- [x] 1.3 Verify POST /oauth/authorize returns proper error responses per RFC 6749 §4.1.2.1
- [x] 1.4 Verify state parameter is preserved from authorize GET through token exchange

## 2. Audit Token Endpoint

- [x] 2.1 Verify POST /oauth/token accepts authorization_code grant with code_verifier
- [x] 2.2 Verify token endpoint accepts client_id in form body (no Basic Auth required)
- [x] 2.3 Test whether refresh_token grant type works (send POST with grant_type=refresh_token)
- [x] 2.4 Verify token response includes access_token, token_type, expires_in, scope fields
- [x] 2.5 Verify Token.Public flag affects client authentication requirements

## 3. Audit Login Flow for Mobile

- [x] 3.1 Verify /login returns JSON error on invalid credentials (not HTML redirect)
- [x] 3.2 Verify /login returns redirect URL on successful login
- [x] 3.3 Verify /api/login returns JSON {ok: true} on success (for programmatic login)
- [x] 3.4 Verify session cookie is set on login response (Set-Cookie header)
- [x] 3.5 Document the complete mobile login flow options (WebView vs programmatic)

## 4. Audit UserInfo and Token Endpoints

- [x] 4.1 Verify GET /userinfo returns claims based on token scopes (openid, profile, email)
- [x] 4.2 Verify GET /test returns RFC 7662 compliant introspection response
- [x] 4.3 Verify POST /oauth/revoke accepts token and token_type_hint per RFC 7678

## 5. Audit Redirect URI and CORS

- [x] 5.1 Verify redirect_uri validation accepts custom URI schemes (myapp://, com.example://)
- [x] 5.2 Verify redirect_uri validation accepts http://127.0.0.1:PORT (common mobile testing pattern)
- [x] 5.3 Verify CORS headers allow mobile app origins (check config.json origins list)
- [x] 5.4 Document CORS configuration needed for WebView-based mobile apps

## 6. Compile Compatibility Matrix

- [x] 6.1 Create a compatibility matrix showing supported/gapped/not-applicable for each OAuth 2.0 / OIDC feature
- [x] 6.2 Document the recommended mobile auth flow with step-by-step instructions
- [x] 6.3 List all gaps and their severity (blocking, warning, non-issue)
- [x] 6.4 Document open questions that need resolution before implementation
