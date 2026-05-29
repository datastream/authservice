## Specification

### Requirement: Serve Vue SPA from static directory

The Go server SHALL serve the built Vue SPA static files from the `./static` directory.

#### Scenario: Serve index.html at root
- **WHEN** a browser requests `GET /`
- **THEN** the server serves the `index.html` file from `./static/`

#### Scenario: Serve SPA assets
- **WHEN** a browser requests `GET /assets/*.js` or `GET /assets/*.css`
- **THEN** the server serves the corresponding asset file from `./static/assets/`

### Requirement: SPA catch-all routing

The Go server SHALL serve the SPA `index.html` for any route that is not an API or OAuth endpoint.

#### Scenario: Unknown route returns SPA
- **WHEN** a browser requests `GET /some/unknown/route` and no API or OAuth route matches
- **THEN** the server serves `index.html` from `./static/` to allow Vue Router to handle the route

#### Scenario: API routes take precedence
- **WHEN** a browser requests `GET /api/login` (a defined API route)
- **THEN** the server serves the API handler, not the SPA

#### Scenario: OAuth routes take precedence
- **WHEN** a browser requests `GET /oauth/authorize` (a defined OAuth route)
- **THEN** the server serves the OAuth handler, not the SPA

### Requirement: Frontend build configuration

The Vue frontend project SHALL build its output to the `./static` directory within the Go server's working directory.

#### Scenario: Build output location
- **WHEN** running `npm run build` in the `frontend/` directory
- **THEN** the output is written to `../static/` which maps to `cmd/oauthservice/static/` in the repository root

### Requirement: Removed Go template rendering

The Go server SHALL no longer render any HTML templates for user-facing pages.

#### Scenario: No ServeStaticHTML usage
- **WHEN** the Go server code is compiled
- **THEN** no controller calls `ServeStaticHTML` or `template.ParseFiles` for user pages

#### Scenario: Removed HTML templates
- **WHEN** the `cmd/oauthservice/static/` directory is inspected at runtime
- **THEN** no `.html` template files exist (only built Vue assets: `index.html`, `assets/`, etc.)
