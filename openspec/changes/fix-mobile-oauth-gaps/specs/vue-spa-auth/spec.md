## MODIFIED Requirements

### Requirement: SPA OAuth authorize redirect MUST point to Vue SPA

The system SHALL redirect unauthenticated or authenticated requests to `/oauth/authorize` to the Vue SPA consent page when rendering is no longer handled by Go templates.

**Current (wrong):**
```go
// AuthPage renders auth.html template which no longer exists
t, err := template.ParseFiles("static/auth.html")
// Returns 500 {"error": "Failed to load auth page"}
```

**Required:**
```go
func AuthPage(c *gin.Context) {
    _, ok, err := middleware.GetLoggedInUserID(c)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    if !ok {
        // Not logged in - redirect to /login
        c.Redirect(http.StatusFound, "/login?"+c.Request.URL.RawQuery)
        return
    }
    // Authenticated - redirect to Vue SPA consent page
    c.Redirect(http.StatusFound, "/consent?"+c.Request.URL.RawQuery)
}
```

#### Scenario: Authenticated GET /oauth/authorize redirects to Vue SPA consent
- **WHEN** a logged-in browser sends `GET /oauth/authorize?client_id=foo&state=bar`
- **THEN** the server returns `302 Found` redirecting to `/consent?client_id=foo&state=bar`

#### Scenario: Unauthenticated GET /oauth/authorize redirects to login
- **WHEN** a not-logged-in browser sends `GET /oauth/authorize?client_id=foo&state=bar`
- **THEN** the server returns `302 Found` redirecting to `/login?client_id=foo&state=bar`

### Requirement: JSON API consent endpoint MUST support programmatic approval

The system SHALL provide `POST /oauth/authorize/approve` for the Vue SPA and mobile apps to programmatically approve OAuth authorization requests.

#### Scenario: Successful consent approval
- **WHEN** a logged-in user sends `POST /oauth/authorize/approve` with valid OAuth authorization parameters
- **THEN** the server generates an authorization code and redirects to `redirect_uri?code=CODE&state=STATE`

#### Scenario: Consent approval with missing parameters
- **WHEN** a client sends `POST /oauth/authorize/approve` without required parameters
- **THEN** the server returns `400 Bad Request` with `{"error": "invalid_request"}`

## REMOVED Requirements

### Requirement: AuthPage renders Go HTML template for consent
**Reason**: All HTML rendering moved to Vue SPA
**Migration**: Use new JSON API consent endpoint or redirect to Vue SPA `/consent` route
