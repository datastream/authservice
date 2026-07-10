## MODIFIED Requirements

### Requirement: SPA catch-all routing MUST NOT intercept OPTIONS preflight

The Go server SHALL serve the SPA `index.html` for any unmatched GET route, but MUST NOT intercept OPTIONS (preflight) requests.

**Current (wrong):**
```go
r.NoRoute(func(c *gin.Context) {
    c.File("./static/index.html")
})
```
This catches ALL HTTP methods including OPTIONS, preventing CORS preflight from reaching the middleware.

**Required:**
```go
r.NoRoute(func(c *gin.Context) {
    if c.Request.Method == "GET" {
        c.File("./static/index.html")
    }
})
```

#### Scenario: OPTIONS preflight reaches CORS middleware
- **WHEN** a browser sends `OPTIONS /api/login` with `Access-Control-Request-Method: POST`
- **THEN** the CORS middleware responds with `200 OK` and proper `Access-Control-*` headers, not the SPA HTML

#### Scenario: SPA catch-all still works for unknown GET routes
- **WHEN** a browser sends `GET /some/unknown/route`
- **THEN** the server serves `index.html` from `./static/` for Vue Router to handle

#### Scenario: POST to unknown route returns 404 (not SPA)
- **WHEN** a non-browser client sends `POST /nonexistent`
- **THEN** the server returns `404 Not Found` (not the SPA HTML)

## REMOVED Requirements

### Requirement: SPA catch-all intercepts all unmatched routes
**Reason**: Replaced by method-aware catch-all
**Migration**: OPTIONS requests now reach CORS middleware; other methods return 404
