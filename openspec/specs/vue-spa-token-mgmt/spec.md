## Specification

### Requirement: List user tokens

The system SHALL provide a JSON API endpoint to list all OAuth tokens owned by the authenticated user.

#### Scenario: Successful token list
- **WHEN** a logged-in user sends `GET /api/tokens`
- **THEN** the server returns `200 OK` with `{"tokens": [{"clientID": "...", "domain": "...", "public": true/false, "describe": "...", "userID": "..."}]}`

#### Scenario: Unauthenticated token list
- **WHEN** a non-logged-in user sends `GET /api/tokens`
- **THEN** the server returns `401 Unauthorized`

### Requirement: Create OAuth token

The system SHALL provide a JSON API endpoint to create new OAuth client tokens.

#### Scenario: Successful token creation
- **WHEN** a logged-in user sends `POST /api/tokens` with `domain` and `public` fields
- **THEN** the server creates a token with the user's ID and returns `200 OK` with `{"ok": true, "clientID": "...", "clientSecret": "..."}`

#### Scenario: Missing required field
- **WHEN** a logged-in user sends `POST /api/tokens` without the `domain` field
- **THEN** the server returns `400 Bad Request` with `{"error": "domain is required"}`

#### Scenario: Token defaults to owner user
- **WHEN** a logged-in user sends `POST /api/tokens` without a `userID` field
- **THEN** the token is created with the logged-in user's ID as the owner

### Requirement: Revoke OAuth token

The system SHALL provide a JSON API endpoint to delete a token owned by the authenticated user.

#### Scenario: Successful token revocation
- **WHEN** a logged-in user sends `DELETE /api/tokens/:clientID` for a token they own
- **THEN** the server deletes the token and returns `200 OK` with `{"ok": true}`

#### Scenario: Cannot revoke another user's token
- **WHEN** a logged-in user sends `DELETE /api/tokens/:clientID` for a token owned by another user
- **THEN** the server returns `403 Forbidden` with `{"error": "Not authorized to delete this token"}`

#### Scenario: Revoke non-existent token
- **WHEN** a logged-in user sends `DELETE /api/tokens/:clientID` for a token that does not exist
- **THEN** the server returns `404 Not Found` with `{"error": "Token not found"}`
