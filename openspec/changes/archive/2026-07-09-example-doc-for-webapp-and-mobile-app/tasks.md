## 1. Create examples directory structure

- [x] 1.1 Create `examples/` directory at project root
- [x] 1.2 Create `examples/web-app/` subdirectory
- [x] 1.3 Create `examples/mobile/` subdirectory

## 2. Write examples/README.md

- [x] 2.1 Document server OAuth endpoints (authorize, token, userinfo, login, logout) with HTTP methods and request/response formats
- [x] 2.2 Add PKCE explanation: code_verifier generation, S256 SHA-256 code_challenge computation
- [x] 2.3 Add ASCII flow diagram showing full authorize → token → userinfo flow
- [x] 2.4 Add redirect URI registration instructions
- [x] 2.5 Add links to web-app and mobile sub-examples

## 3. Build web-app example

- [x] 3.1 Create `examples/web-app/index.html` with login, authorize, and callback pages
- [x] 3.2 Create `examples/web-app/app.js` implementing the full OAuth Code Flow with PKCE:
  - Generate random code_verifier and SHA-256 code_challenge
  - Redirect to `/oauth/authorize` with PKCE params
  - Parse `code` and `state` from redirect callback
  - Exchange code for access token via `POST /oauth/token` with code_verifier
  - Fetch userinfo via `GET /userinfo` with Bearer token
  - Display user profile on page
- [x] 3.3 Create `examples/web-app/server.js` (Express static server) to serve the app locally
- [x] 3.4 Add `package.json` with minimal dependencies (express only)
- [x] 3.5 Add error handling for denied consent, invalid state, network errors

## 4. Build mobile app reference

- [x] 4.1 Create `examples/mobile/token-exchange.sh` — curl script demonstrating the full token exchange:
  - Generate random code_verifier and SHA-256 code_challenge
  - Print authorize URL for manual visit
  - Parse authorization code (manual input or mock)
  - Exchange code for access token via POST
  - Fetch userinfo
- [x] 4.2 Create `examples/mobile/README.md` with:
  - Explanation of mobile-specific security considerations (public clients)
  - iOS integration notes (SFSafariViewController / ASWebAuthenticationSession)
  - Android integration notes (CustomTabs / AppLinks)
  - Token storage recommendations (Keychain/Keystore)
  - Mapping of each curl step to native SDK equivalent

## 5. Final review

- [x] 5.1 Verify all files are syntactically correct (JS parses, shell script is valid)
- [x] 2. Verify README is complete and readable as standalone documentation
- [x] 5.3 Ensure no secrets, tokens, or credentials are committed
- [x] 5.4 Add a brief note in README about verifying examples against the latest server version
