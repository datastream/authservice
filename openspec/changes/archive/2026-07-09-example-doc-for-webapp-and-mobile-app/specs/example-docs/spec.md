## ADDED Requirements

### Requirement: Integration README at examples root

The `examples/README.md` file SHALL document all OAuth 2.0 endpoints used by clients and provide a step-by-step integration guide.

#### Scenario: README documents server endpoints
- **WHEN** a developer reads `examples/README.md`
- **THEN** they find the base URL, authorize endpoint (`/oauth/authorize`), token endpoint (`/oauth/token`), and userinfo endpoint (`/userinfo`) with HTTP methods and expected request/response formats

#### Scenario: README explains PKCE flow
- **WHEN** a developer reads the integration guide in `examples/README.md`
- **THEN** they find a step-by-step walkthrough of the Authorization Code Flow with PKCE, including how to generate `code_verifier` and `code_challenge`

#### Scenario: README shows redirect URI registration
- **WHEN** a developer reads `examples/README.md`
- **THEN** they find instructions on how to register a redirect URI with the server via the consent page

### Requirement: Web app reference implementation

The `examples/web-app/` directory SHALL contain a complete, runnable single-page application that implements the full OAuth flow.

#### Scenario: Web app includes all required files
- **WHEN** a developer looks in `examples/web-app/`
- **THEN** they find `index.html`, `app.js`, and a static file server configuration (e.g., `server.js` using Express or Python `http.server`)

#### Scenario: Web app generates PKCE parameters
- **WHEN** the web app initiates the authorization flow
- **THEN** it generates a `code_verifier` (43-128 random characters) and computes a `code_challenge` using SHA-256 (S256 method)

#### Scenario: Web app handles authorize redirect
- **WHEN** the user clicks "Authorize" on the consent page
- **THEN** the browser is redirected to the authorization code callback URL with a `code` and `state` parameter appended to the redirect URI

#### Scenario: Web app exchanges code for token
- **WHEN** the web app receives the authorization code in the callback URL
- **THEN** it sends a `POST /oauth/token` request with the code, `code_verifier`, `client_id`, `redirect_uri`, and `grant_type=authorization_code`, receiving an access token in the response

#### Scenario: Web app fetches userinfo
- **WHEN** the web app has a valid access token
- **THEN** it sends a `GET /userinfo` request with the `Authorization: Bearer <token>` header and displays the user profile information

#### Scenario: Web app handles login redirect for unauthenticated users
- **WHEN** an unauthenticated user visits the authorize page
- **THEN** the app redirects to `/login`, then back to `/oauth/authorize` after successful login, preserving all query parameters

#### Scenario: Web app displays error messages
- **WHEN** the OAuth flow fails (e.g., user denied consent, invalid state)
- **THEN** the web app displays an error message from the error parameter returned in the redirect URI

### Requirement: Mobile app reference implementation

The `examples/mobile/` directory SHALL contain a reference implementation demonstrating the OAuth token exchange flow for mobile applications.

#### Scenario: Mobile reference includes curl-based token exchange script
- **WHEN** a developer looks in `examples/mobile/`
- **THEN** they find a shell script that uses `curl` to demonstrate the full token exchange: generating PKCE parameters, redirecting to authorize, extracting the code, and exchanging for a token

#### Scenario: Mobile reference documents native integration
- **WHEN** a developer reads the mobile README in `examples/mobile/`
- **THEN** they find platform-specific notes for implementing the flow in iOS (using `SFSafariViewController` or `ASWebAuthenticationSession`) and Android (using `CustomTabs` or `AppLinks`)

#### Scenario: Mobile reference warns about public client security
- **WHEN** a developer reads the mobile documentation
- **THEN** they find a warning that mobile apps are public clients that cannot securely store client secrets, and instructions to use PKCE (S256) as the recommended mitigation
