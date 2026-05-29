## 1. Frontend: Replace React with Vue + configure Vite

- [x] 1.1 Replace react/react-dom with vue in frontend/package.json
- [x] 1.2 Replace @vitejs/plugin-react with @vitejs/plugin-vue in vite.config.ts
- [x] 1.3 Convert App.tsx to App.vue using Vue 3 Composition API
- [x] 1.4 Remove index.html root content placeholder, replace with Vue app mount
- [x] 1.5 Ensure Tailwind CSS still works with Vue file extensions (update tailwind.config.cjs content patterns)
- [x] 1.6 Verify `npm run build` succeeds and outputs to cmd/oauthservice/static/
- [x] 1.7 Remove node_modules and reinstall with Vue dependencies

## 2. Frontend: Implement Vue pages and routing

- [x] 2.1 Create `src/router/index.ts` with Vue Router for login, signup, and token-manager routes
- [x] 2.2 Create `src/pages/LoginPage.vue` with login form, error display, and fetch-based POST to /api/login
- [x] 2.3 Create `src/pages/SignupPage.vue` with registration form, validation, and fetch-based POST to /api/signup
- [x] 2.4 Create `src/pages/TokenManagerPage.vue` with token list, create form, and revoke buttons (migrate from tokens.html JS logic)
- [x] 2.5 Create `src/App.vue` with navigation bar (login/signup/logout links) and router-view
- [x] 2.6 Create `src/components/ErrorMessage.vue` shared error display component
- [x] 2.7 Add global styles in `src/style.css` using Tailwind directives (`@tailwind base; @tailwind components; @tailwind utilities;`)

## 3. Frontend: Implement auth composable and API client

- [x] 3.1 Create `src/composables/useAuth.ts` with login(), signup(), logout(), checkSession() functions
- [x] 3.2 Create `src/api/tokens.ts` for token CRUD operations (list, create, delete)
- [x] 3.3 Configure axios or fetch wrapper with `credentials: 'include'` for cookie-based auth
- [x] 3.4 Add navigation guard in router to redirect unauthenticated users from protected routes

## 4. Backend: Add new API endpoints

- [x] 4.1 Create `pkg/controllers/api.go` with LoginAPI, SignupAPI, LogoutAPI handlers returning JSON
- [x] 4.2 Implement LoginAPI: POST /api/login — validates credentials, resets session, returns `{"ok": true}`
- [x] 4.3 Implement SignupAPI: POST /api/signup — creates user, resets session, returns `{"ok": true}`
- [x] 4.4 Implement LogoutAPI: POST /api/logout — flushes session, returns `{"ok": true}`
- [x] 4.5 Implement MeAPI: GET /api/me — checks session, returns `{"username": "..."}` or 401
- [x] 4.6 Wire all new API routes under `/api/*` prefix in main.go

## 5. Backend: Update existing API endpoints

- [x] 5.1 Update `controllers.TokensList` handler to work with `/api/tokens` route
- [x] 5.2 Update `controllers.ClientTokensCreate` handler to work with `/api/tokens` route
- [x] 5.3 Update `controllers.TokenRevoke` handler to work with `/api/tokens/:id` route
- [x] 5.4 Remove `Managerpage` handler (no longer serves Go HTML template)

## 6. Backend: Serve Vue SPA from Go

- [x] 6.1 Add `r.Static("/static", "./static")` in main.go to serve built Vue assets
- [x] 6.2 Add catch-all route `r.NoRoute()` that serves `./static/index.html` for non-API/OAuth routes
- [x] 6.3 Remove all `ServeStaticHTML` calls and template parsing from controllers (kept as fallbacks for login page & OAuth consent)
- [x] 6.4 Remove or mark as deprecated the `pkg/middleware/static_server.go` file (kept for fallback rendering)

## 7. Backend: Update OAuth consent flow for SPA

- [x] 7.1 Add `/api/me` check inline in the `/oauth/authorize` GET handler for SPA awareness
- [x] 7.2 When session is not found at `/oauth/authorize`, redirect browser to `/login` with preserved query params
- [x] 7.3 Keep the existing consent form rendering for authenticated session requests (unchanged from current behavior)

## 8. Cleanup: Remove old Go templates and dead code

- [x] 8.1 Delete `cmd/oauthservice/static/login.html`
- [x] 8.2 Delete `cmd/oauthservice/static/signup.html`
- [x] 8.3 Delete `cmd/oauthservice/static/auth.html`
- [x] 8.4 Keep `cmd/oauthservice/static/tokens.html` until Vue TokenManagerPage is verified working
- [x] 8.5 Remove `template` import from `pkg/controllers/oauth.go`
- [x] 8.6 Remove dead `frontend/` React scaffold files (App.tsx, App.css)
- [x] 8.7 Verify `go vet ./...` passes with no errors

## 9. Verification: Build and smoke test

- [x] 9.1 Build the Vue SPA: `cd frontend && npm run build`
- [x] 9.2 Start the Go server and verify routes load
- [x] 9.3 Verify `GET /` serves the Vue SPA (200 OK, index.html)
- [x] 9.4 Verify login flow: POST /api/login → session cookie → GET /api/me returns username
- [x] 9.5 Verify signup flow: POST /api/signup with email → session cookie → /api/me returns username
- [x] 9.6 Verify token CRUD: list (empty), create (returns clientID/secret), list (1 token), revoke (ok), list (empty)
- [x] 9.7 Verify logout: POST /api/logout → session destroyed → /api/me returns 401
- [x] 9.8 Verify `/oauth/authorize` flow: unauthenticated → redirect to /login?client_id=..., authenticated → consent page
