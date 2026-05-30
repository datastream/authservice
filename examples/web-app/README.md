# Web App OAuth 2.0 PKCE Example

A complete runnable example demonstrating the OAuth 2.0 Authorization Code Flow with PKCE for a browser-based single-page application.

## Files

| File | Description |
|------|-------------|
| `index.html` | Main app page — login form, authorize button, profile display |
| `callback.html` | Callback handler page — processes the OAuth code response |
| `app.js` | All JavaScript logic — PKCE generation, fetch calls, UI updates |
| `styles.css` | Minimal CSS styles |
| `server.js` | Express static file server (runs the example app) |
| `package.json` | Dependencies (only `express`) |

## Prerequisites

- Node.js 18+
- A running OAuth 2.0 server (set `BASE_URL` in `app.js`)
- A registered OAuth client with:
  - `client_id`: `web-app-example`
  - `redirect_uri`: `http://localhost:3000/callback.html`
  - CORS configured for `http://localhost:3000`

## Running the Example

```bash
# Install dependencies
cd examples/web-app
npm install

# Start the example app (serves on http://localhost:3000)
npm start
```

Then open `http://localhost:3000` in your browser.

## How It Works

1. **User clicks "Authorize"** → the app generates a `code_verifier` and `code_challenge` (SHA-256) and redirects the browser to `/oauth/authorize`
2. **User authenticates and consents** → if not logged in, the server redirects to `/api/login` first
3. **Server redirects back** → with `?code=AUTH_CODE&state=STATE` appended to `callback.html`
4. **App exchanges code for token** → POST `/oauth/token` with the authorization code and original `code_verifier`
5. **App fetches userinfo** → GET `/userinfo` with the access token as Bearer header
6. **App displays user profile** → JSON output in the UI

## Security Notes

- The `code_verifier` is stored in `sessionStorage` — cleared when the tab closes
- The `state` parameter protects against CSRF attacks
- The code_challenge uses S256 (SHA-256) method per RFC 7636
- No client secret is used (public client)

## Adapting for Your Project

1. Change `client_id` in `app.js` to match your registered client
2. Update `BASE_URL` to point to your OAuth server
3. Update `redirect_uri` in both `app.js` and the callback URL to match your domain
4. Ensure your server's CORS configuration allows requests from your app's origin
