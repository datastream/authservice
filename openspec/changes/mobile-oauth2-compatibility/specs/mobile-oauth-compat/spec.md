## ADDED Requirements

### Requirement: Authorization Code Flow with PKCE MUST work for mobile clients

The server MUST support the OAuth 2.0 authorization code flow with PKCE for public mobile clients.

#### Scenario: Authorize request with PKCE S256
- **WHEN** a mobile app sends GET `/oauth/authorize?client_id=X&redirect_uri=myapp://callback&response_type=code&code_challenge=Z&code_challenge_method=S256&state=ABC`
- **THEN** the server accepts the request, validates PKCE challenge, and renders the consent page (or redirects to login if not authenticated)

#### Scenario: PKCE challenge is mandatory
- **WHEN** a request to `/oauth/authorize` omits `code_challenge`
- **THEN** the server rejects with `error=missing_code_challenge` (per RFC 7636)

#### Scenario: Authorization response includes code and state
- **WHEN** user approves consent on the authorize POST endpoint
- **THEN** the server redirects to `redirect_uri?code=AUTH_CODE&state=ABC`

#### Scenario: Code exchange at token endpoint
- **WHEN** the mobile app sends POST `/oauth/token` with `grant_type=authorization_code&code=CODE&code_verifier=VERIFIER&client_id=X&redirect_uri=myapp://callback`
- **THEN** the server validates the code_verifier against the stored code_challenge and returns access_token + token_type

### Requirement: Token Endpoint MUST support public client authentication

Mobile apps are public clients and MUST be able to exchange authorization codes for tokens without a client_secret.

#### Scenario: Token request with client_id in form body
- **WHEN** the mobile app sends POST `/oauth/token` with `client_id` in the form body (no Basic Auth header)
- **THEN** the server accepts the client_id and processes the token request

#### Scenario: Token request with Basic Auth
- **WHEN** the mobile app sends POST `/oauth/token` with `client_id:client_secret` in the Authorization header
- **THEN** the server accepts and processes the token request

#### Scenario: Refresh token grant support
- **WHEN** the mobile app sends POST `/oauth/token` with `grant_type=refresh_token&refresh_token=REFRESH`
- **THEN** the server either processes the refresh or returns a documented error

### Requirement: Userinfo Endpoint MUST return profile data for mobile clients

The server MUST provide user profile information via the UserInfo endpoint using bearer token authentication.

#### Scenario: UserInfo request with openid scope
- **WHEN** the mobile app sends GET `/userinfo` with `Authorization: Bearer ACCESS_TOKEN`
- **THEN** the server returns `{"sub": "username", ...}` with claims based on requested scopes

#### Scenario: Profile scope returns name claim
- **WHEN** the access token includes `profile` scope
- **THEN** the UserInfo response includes the `name` field

#### Scenario: Email scope returns email claims
- **WHEN** the access token includes `email` scope
- **THEN** the UserInfo response includes `email` and `email_verified` fields

### Requirement: OIDC Discovery Endpoint MUST be accessible

Mobile apps MUST be able to discover server capabilities via the OIDC discovery endpoint.

#### Scenario: GET /.well-known/openid-configuration
- **WHEN** a mobile app requests `GET /.well-known/openid-configuration`
- **THEN** the server returns valid JSON with `issuer`, `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `scopes_supported`, and `response_types_supported`

#### Scenario: response_types_supported reflects actual capabilities
- **WHEN** the discovery response is parsed
- **THEN** `response_types_supported` contains only `code` (the only supported type)

### Requirement: Token Revocation MUST be RFC 7678 compliant

Mobile apps MUST be able to revoke access tokens when users log out.

#### Scenario: Revoke a token
- **WHEN** the mobile app sends POST `/oauth/revoke` with `token=ACCESS_TOKEN&token_type_hint=access_token`
- **THEN** the server revokes the token and returns `{"status": "ok"}`

#### Scenario: Revoke with missing token
- **WHEN** the mobile app sends POST `/oauth/revoke` without a token
- **THEN** the server returns `{"error": "missing token"}` with HTTP 400

### Requirement: Token Introspection MUST be RFC 7662 compliant

Mobile apps and backend services MUST be able to validate access tokens via introspection.

#### Scenario: Introspect a valid token
- **WHEN** the mobile app or backend service sends POST `/test` with a valid bearer token
- **THEN** the server returns `{"active": true, "scope": "...", "client_id": "...", "user": "...", "iat": ..., "exp": ...}`

#### Scenario: Introspect an invalid token
- **WHEN** the mobile app sends POST `/test` with an invalid or expired token
- **THEN** the server returns `{"active": false}` with HTTP 200

## REMOVED Requirements

None yet — this is a new assessment. Existing specs for authorization code flow, PKCE, state parameter, and consent flow remain unchanged.
