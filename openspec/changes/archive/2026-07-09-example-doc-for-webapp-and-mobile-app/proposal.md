## Why

Third-party developers integrating with this OAuth 2.0 authorization server need concrete, runnable examples for web and mobile clients. Currently there is no documentation showing how to implement the full authorization code flow with PKCE, token exchange, and userinfo retrieval — forcing developers to read source code to reverse-engineer the integration.

## What Changes

- Add `examples/` directory with complete client implementations:
  - **Web App example** — vanilla JS / single-page app using Authorization Code Flow with PKCE, stored in a minimal `examples/web-app/` directory with `index.html`, `app.js`, and a Node/Express static server
  - **Mobile App example** — simulated mobile client (using `curl` + shell script for token exchange, plus a README describing the native iOS/Android flow)
- Add a root-level `examples/README.md` explaining the OAuth flows, the server endpoints, and step-by-step integration instructions
- Document PKCE setup, redirect URI registration, token refresh (if supported), and error handling

## Capabilities

### New Capabilities
- `example-docs`: Example integration documentation and reference client implementations for web and mobile OAuth flows

### Modified Capabilities
<!-- None — this is documentation-only, no spec-level behavior changes -->

## Impact

- Adds new `examples/` directory with markdown docs, JavaScript, and shell scripts
- No changes to server code, OAuth behavior, or existing APIs
- No breaking changes
