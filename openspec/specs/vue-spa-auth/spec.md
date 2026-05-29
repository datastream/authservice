## Specification

### Requirement: SPA login via JSON API

The system SHALL provide a JSON API endpoint for SPA-based login that does not perform HTTP redirects.

#### Scenario: Successful login
- **WHEN** a client sends `POST /api/login` with valid `username` and `password` in the request body
- **THEN** the server validates credentials, creates a new session, and returns `200 OK` with `{"ok": true}`

#### Scenario: Failed login
- **WHEN** a client sends `POST /api/login` with invalid credentials
- **THEN** the server returns `401 Unauthorized` with `{"error": "Invalid credentials"}`

#### Scenario: Login preserves query parameters
- **WHEN** a client sends `POST /api/login?client_id=foo&redirect_uri=...` with valid credentials
- **THEN** the server creates a session and the SPA can navigate to `/oauth/authorize?client_id=foo&redirect_uri=...`

### Requirement: SPA signup via JSON API

The system SHALL provide a JSON API endpoint for SPA-based user registration.

#### Scenario: Successful registration
- **WHEN** a client sends `POST /api/signup` with valid `username`, `email`, and `password`
- **THEN** the server creates the user, starts a new session, and returns `200 OK` with `{"ok": true}`

#### Scenario: Duplicate username
- **WHEN** a client sends `POST /api/signup` with an existing username
- **THEN** the server returns `409 Conflict` with `{"error": "Username already exists"}`

#### Scenario: Invalid email format
- **WHEN** a client sends `POST /api/signup` with an invalid email
- **THEN** the server returns `400 Bad Request` with `{"error": "Invalid email format"}`

### Requirement: SPA logout

The system SHALL provide a JSON API endpoint for SPA-based logout.

#### Scenario: Successful logout
- **WHEN** a client sends `POST /api/logout`
- **THEN** the server flushes the session and returns `200 OK` with `{"ok": true}`

### Requirement: Session check endpoint

The system SHALL provide an endpoint for the SPA to check the current authentication state.

#### Scenario: User is logged in
- **WHEN** a client sends `GET /api/me` with a valid session cookie
- **THEN** the server returns `200 OK` with `{"username": "..."}`

#### Scenario: User is not logged in
- **WHEN** a client sends `GET /api/me` without a valid session
- **THEN** the server returns `401 Unauthorized` with `{"error": "Not authenticated"}`

### Requirement: SPA-aware OAuth authorize redirect

The system SHALL redirect unauthenticated requests to the SPA login page when accessing `/oauth/authorize`.

#### Scenario: Unauthenticated GET /oauth/authorize
- **WHEN** a browser sends `GET /oauth/authorize?client_id=foo` without a session
- **THEN** the server returns a `302` redirect to `/login?client_id=foo&...` preserving all query parameters

#### Scenario: Authenticated GET /oauth/authorize
- **WHEN** a browser sends `GET /oauth/authorize?client_id=foo` with a valid session
- **THEN** the server renders the consent page with client information
