# OAuth 2.0 Integration Examples

Reference implementations for integrating with this OAuth 2.0 authorization server.

## Server Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/.well-known/openid-configuration` | OpenID Connect discovery metadata |
| GET | `/oauth/authorize` | Authorization page (redirects to consent UI) |
| POST | `/oauth/authorize` | Internal handler for generating authorization codes (called by library) |
| POST | `/oauth/token` | Token endpoint — exchange authorization code for access token |
| GET | `/userinfo` | Userinfo endpoint — get user profile with a valid access token |
| POST | `/login` | Login endpoint — authenticate user by username/password |
| POST | `/logout` | Logout endpoint — clear user session |
| POST | `/token` | Token revocation (RFC 7678) |

### Login Request / Response

**Request:** `POST /login`

```json
{ "username": "johndoe", "password": "secret" }
```

**Success (200):**

```json
{ "message": "Login successful", "redirect": "/oauth/authorize?client_id=..." }
```

**Failure (401):**

```json
{ "error": "Invalid credentials" }
```

### Token Request / Response

**Request:** `POST /oauth/token`

Body: `application/x-www-form-urlencoded`

| Parameter | Required | Description |
|-----------|----------|-------------|
| `grant_type` | Yes | Must be `authorization_code` |
| `code` | Yes | Authorization code from the authorize redirect |
| `redirect_uri` | Yes | Must match the registered redirect URI |
| `client_id` | Yes | Registered client identifier |
| `code_verifier` | Yes | PKCE code_verifier (for public clients) |

**Success (200):**

```json
{
  "access_token": "eyJ...",
  "token_type": "bearer",
  "expires_in": 3600,
  "scope": "openid profile email"
}
```

### Userinfo Request / Response

**Request:** `GET /userinfo`

Header: `Authorization: Bearer <access_token>`

**Success (200):**

```json
{ "sub": "johndoe" }
```

With `profile` scope:

```json
{ "sub": "johndoe", "name": "johndoe" }
```

With `email` scope:

```json
{ "sub": "johndoe", "email": "johndoe@example.com", "email_verified": true }
```

## Authorization Code Flow with PKCE

This server uses the Authorization Code Flow with PKCE (RFC 7636). PKCE prevents authorization code interception attacks and is required for all clients (including public clients like SPAs and mobile apps).

### Flow Diagram

```
Client                          Server
  |                               |
  |--- POST /login -------------->| (username + password)
  |<-- 200 OK (session set) ------|
  |                               |
  |--- GET /oauth/authorize ------>| (client_id, redirect_uri, state,
  |                               |  code_challenge=S256, response_type=code)
  |<-- 302 to /consent -----------|
  |                               |
  |--- User approves consent ---->|
  |<-- 302 to redirect_uri?code=X&state=Y -|
  |                               |
  |--- POST /oauth/token -------->| (code, client_id, redirect_uri,
  |                               |  code_verifier, grant_type=authorization_code)
  |<-- 200 OK (access_token) -----|
  |                               |
  |--- GET /userinfo ------------>| (Authorization: Bearer <token>)
  |<-- 200 OK (user profile) -----|
```

### Step-by-Step

1. **Generate PKCE parameters**
   - Generate a random `code_verifier` (43-128 characters, ASCII alphanumeric, hyphen, period, underscore, tilde)
   - Compute `code_challenge` = Base64UrlEncode(SHA256(code_verifier)) for S256 method
   - Store `code_verifier` securely for the token exchange step

2. **Redirect to authorize endpoint**
   ```
   GET /oauth/authorize?
     response_type=code
     &client_id=YOUR_CLIENT_ID
     &redirect_uri=YOUR_REDIRECT_URI
     &code_challenge=BASE64URL_SHA256(verifier)
     &code_challenge_method=S256
     &state=RANDOM_STATE
   ```

3. **User authenticates and consents**
   - If not logged in, server redirects to `/login` first
   - After login, server shows consent page
   - User approves → browser redirected to `redirect_uri?code=AUTH_CODE&state=STATE`

4. **Exchange code for token**
   ```
   POST /oauth/token
   Content-Type: application/x-www-form-urlencoded

   grant_type=authorization_code
   &code=AUTH_CODE
   &redirect_uri=YOUR_REDIRECT_URI
   &client_id=YOUR_CLIENT_ID
   &code_verifier=ORIGINAL_VERIFIER
   ```

5. **Use access token**
   ```
   GET /userinfo
   Authorization: Bearer ACCESS_TOKEN
   ```

### Error Handling

The server returns standard OAuth 2.0 error parameters in the redirect URI:

| Error Value | Description |
|-------------|-------------|
| `invalid_request` | Missing or invalid parameters |
| `unauthorized_client` | Client ID not registered |
| `access_denied` | User denied consent |
| `invalid_grant` | Invalid authorization code or code_verifier mismatch |
| `server_error` | Internal server error |

Example error redirect:
```
YOUR_REDIRECT_URI?error=access_denied&error_description=User+denied+consent
```

## Example Clients

### [web-app/](web-app/) — Vanilla JS Single-Page Application

A complete runnable web app demonstrating the full OAuth flow:
- PKCE parameter generation (SHA-256)
- Browser-based authorize redirect
- Authorization code callback parsing
- Token exchange via POST
- Userinfo retrieval
- Login redirect handling
- Error display

See [web-app/README.md](web-app/README.md) for instructions to run.

### [mobile/](mobile/) — Mobile App Reference

Shell-based reference implementation using curl, plus platform-specific integration notes:
- PKCE generation via shell utilities
- Manual token exchange walkthrough
- iOS integration (ASWebAuthenticationSession)
- Android integration (CustomTabs)
- Public client security considerations

See [mobile/README.md](mobile/README.md) for details.

### [cli/](cli/) — Go Command-Line Client

A Go CLI for authenticating and managing OAuth client tokens:
- Session-based authentication via `POST /login`
- User profile lookup via `/userinfo`
- Token CRUD: list, create, revoke OAuth client tokens
- File-based credential cache (`~/.authservice/creds.json`)

**Usage:**

```bash
# Build and run
cd examples/cli
go build -o authcli .

# Authenticate
./authcli -s http://localhost:8080 login johndoe secret

# View profile
./authcli -s http://localhost:8080 me

# Manage OAuth client tokens
./authcli -s http://localhost:8080 tokens list
./authcli -s http://localhost:8080 tokens create -d "my-app"
./authcli -s http://localhost:8080 tokens revoke <client-id>
```

## Verifying Examples

These examples are written against the current server implementation. If you encounter discrepancies, verify against the live server endpoints listed in the OpenID discovery document:

```bash
curl https://YOUR_SERVER_HOST/.well-known/openid-configuration
```
