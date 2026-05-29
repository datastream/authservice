## ADDED Requirements

### Requirement: All HTTP status codes SHALL use `http.StatusOK` constant instead of bare integers

All response handlers SHALL use `http.StatusOK` (value 200) instead of the bare integer `200` for successful responses.

#### Scenario: Successful token listing returns http.StatusOK
- **WHEN** `GET /tokens` succeeds
- **THEN** the response uses `c.JSON(http.StatusOK, ...)` not `c.JSON(200, ...)`

#### Scenario: Successful FGA model creation returns http.StatusOK
- **WHEN** `POST /fga/models` succeeds
- **THEN** the response uses `c.JSON(http.StatusOK, ...)` not `c.JSON(200, ...)`

### Requirement: Error responses SHALL use the `"error"` key consistently

All error responses SHALL use the key `"error"` (lowercase) for error messages. No handler SHALL use `"Status"` (capital S) for error responses.

#### Scenario: Token auth failure returns "error" key
- **WHEN** `TokenAuth` receives an invalid token type
- **THEN** the response uses `gin.H{"error": "..."}` not `gin.H{"Status": "..."}`

#### Scenario: Login endpoint errors use "error" key
- **WHEN** a login request fails (invalid body, user not found)
- **THEN** the response uses `gin.H{"error": "..."}` not `gin.H{"Status": "..."}`

### Requirement: Request-scoped contexts SHALL replace context.TODO() and context.Background()

All handler-level functions SHALL use `c.Request.Context()` for session operations and permission checks instead of `context.TODO()` or `context.Background()`.

#### Scenario: Session operations respect request cancellation
- **WHEN** a client disconnects during session creation
- **THEN** the session operation is cancelled (the call returns with a context error)

#### Scenario: FGA permission checks respect request cancellation
- **WHEN** a client disconnects during an FGA permission check
- **THEN** the FGA API call is cancelled
