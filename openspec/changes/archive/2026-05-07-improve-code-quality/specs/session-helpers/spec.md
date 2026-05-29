## ADDED Requirements

### Requirement: RequireLogin helper SHALL reduce logged-in user checks to a single call

The `middleware` package SHALL provide a `RequireLogin` function that starts a session, extracts `LoggedInUserID`, and aborts the handler with a 302 redirect to `/login` if the user is not authenticated.

#### Scenario: Logged-in user proceeds
- **WHEN** a handler calls `RequireLogin(c)` and the session contains a valid `LoggedInUserID`
- **THEN** the function returns the user ID string and the handler continues

#### Scenario: Unauthenticated user is redirected
- **WHEN** a handler calls `RequireLogin(c)` and the session does not contain `LoggedInUserID`
- **THEN** the function calls `c.AbortWithStatusJSON(http.StatusFound, gin.H{"message": "Not logged in", "redirect": "/login"})` with a `Location: /login` header

#### Scenario: Session start failure returns 500
- **WHEN** a handler calls `RequireLogin(c)` and session creation fails
- **THEN** the function calls `c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": <session error message>})`

### Requirement: ServeStaticHTML SHALL replace inline file-serving code

All controllers SHALL use the existing `middleware.ServeStaticHTML` function instead of manually opening, stat'ing, and reading HTML files.

#### Scenario: Existing HTML file is served correctly
- **WHEN** `ServeStaticHTML(c, "static/login.html")` is called for an existing file
- **THEN** the file content is sent with `Content-Type: text/html; charset=utf-8` and status 200

#### Scenario: Missing file returns 404
- **WHEN** `ServeStaticHTML(c, "static/missing.html")` is called for a non-existent file
- **THEN** the handler calls `c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"Status": "File not found"})`
