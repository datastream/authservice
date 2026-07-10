## ADDED Requirements

### Requirement: Clients MUST support redirect URI registration

The system SHALL allow users to register one or more redirect URIs for each OAuth client token.

#### Scenario: Add redirect URI to existing client
- **WHEN** a logged-in user sends `POST /api/tokens/:clientID/redirectUris` with `{"redirectUri": "myapp://localhost/callback"}`
- **THEN** the system adds the redirect URI to the client and returns `{"ok": true, "redirectUri": "myapp://localhost/callback"}`

#### Scenario: Add multiple redirect URIs
- **WHEN** a user sends `POST /api/tokens/:clientID/redirectUris` with one URI and then again with a different URI
- **THEN** both URIs are registered and both are accepted during the OAuth flow

#### Scenario: Remove redirect URI
- **WHEN** a logged-in user sends `DELETE /api/tokens/:clientID/redirectUris?redirectUri=myapp://localhost/callback`
- **THEN** the system removes that redirect URI and returns `{"ok": true}`

#### Scenario: User cannot modify another user's redirect URIs
- **WHEN** user A sends `POST /api/tokens/:clientID/redirectUris` for a token owned by user B
- **THEN** the system returns `403 Forbidden` with `{"error": "Not authorized"}`

### Requirement: Redirect URI validation MUST support custom URI schemes

The system SHALL validate redirect URIs against registered URIs, supporting custom schemes (e.g., `myapp://`, `com.example://`) used by mobile apps.

#### Scenario: Custom scheme matches registered URI
- **WHEN** a client sends `GET /oauth/authorize?redirect_uri=myapp://localhost/callback` and `myapp://localhost/callback` is registered for that client
- **THEN** the server accepts the redirect URI and proceeds with authorization

#### Scenario: Custom scheme does not match registered URI
- **WHEN** a client sends `GET /oauth/authorize?redirect_uri=myapp://different/callback` and `myapp://different/callback` is not registered
- **THEN** the server rejects with `error=invalid_request` and `error_description` explaining the redirect URI mismatch

#### Scenario: HTTP localhost redirect URI matches
- **WHEN** a client sends `GET /oauth/authorize?redirect_uri=http://127.0.0.1:8080/callback` and it is registered for the client
- **THEN** the server accepts the redirect URI

#### Scenario: Registered URI matches request URI exactly
- **WHEN** a client has `https://app.example.com/callback` registered and sends `https://app.example.com/callback` in the request
- **THEN** the server accepts the redirect URI

#### Scenario: No redirect URI registered falls back to domain comparison
- **WHEN** a client has no redirect URI registered and sends a request with `redirect_uri=http://example.com/callback`
- **THEN** the server accepts the redirect URI if the host matches the client's Domain field (backward compatibility)
