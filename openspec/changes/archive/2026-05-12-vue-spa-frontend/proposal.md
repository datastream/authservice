## Why

The auth server's web UI is scattered across 4 Go HTML templates with inline CSS and mixed patterns — no shared layout, no error display on login, inconsistent styling, and a broken login redirect flow for browsers. The `frontend/` directory has a dead Vite + React scaffold that was never wired up. We need a proper, unified SPA for all user-facing pages.

## What Changes

- Replace all Go HTML templates (`login.html`, `signup.html`, `auth.html`, `tokens.html`) with a single-page Vue 3 application
- Convert Go handlers for login, logout, signup, and token management to return JSON APIs under `/api/*`
- Serve the built Vue SPA from `static/` (current build output target)
- Keep OAuth 2.0 server endpoints (`/oauth/*`, `/userinfo`, `/test`) unchanged — these are for external OAuth clients, not users
- Remove `ServeStaticHTML` and all Go template rendering from controllers
- Add a new SPA-aware login/signup flow: POST returns JSON success, SPA follows redirect to `/oauth/authorize`
- Add `/api/me` endpoint for session checking (used by SPA to determine auth state)
- Update token management endpoints to work with the SPA (CRUD via fetch)
- Replace React dependencies with Vue 3 in the `frontend/` project
- Use Tailwind CSS for styling (already configured)

## Capabilities

### New Capabilities

- `vue-spa`: Vue 3 + Vite + TypeScript + Tailwind single-page application for login, signup, OAuth consent, and token management

### Modified Capabilities

<!-- No existing spec-level capabilities are being modified — this is a new frontend architecture -->

## Impact

- **Removed**: `ServeStaticHTML` middleware, all Go HTML templates (`*.html` in `static/`), template rendering in controllers (`login.go`, `oauth.go`, `register.go`, `tokens.go`)
- **Changed**: Login/signup/logout endpoints move from form-POST → JSON API under `/api/login`, `/api/signup`, `/api/logout`
- **Added**: `/api/me` endpoint for session check, Vue SPA build pipeline, `r.Static("/", "./static")` route, catch-all route for SPA routing
- **Dependencies**: Replace `react`/`react-dom` with `vue` in `frontend/package.json`, add `@vitejs/plugin-vue`
- **Unchanged**: OAuth server endpoints (`/oauth/*`), `/userinfo`, `/test`, FGA endpoints, CORS config, session middleware
