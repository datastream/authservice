## 1. Fix OAuth authorize error responses (RFC 6749 §4.1.2.1)

- [ ] **1.1 Remove redundant session check in OAuthHandler**
  - File: `pkg/controllers/oauth.go`
  - Remove lines 135-149 (the `_, ok, err := middleware.GetLoggedInUserID(c)` check and the JSON error returns)
  - The library's `userAuthorizeHandler` (service.go:232-245) already handles unauthenticated users with a 302 redirect to /login
  - The `HandleAuthorizeRequest` call (line 151) should remain — it will trigger the library's built-in redirect flow
  - This eliminates the JSON-vs-redirect mismatch for unauthenticated POST /oauth/authorize requests

- [ ] **1.2 Verify library redirect behavior**
  - Confirm that when `userAuthorizeHandler` returns empty userID (no session), the library emits a 302 redirect with the original query params preserved
  - No code change needed — the library handles this in `HandleAuthorizeRequest`

## 2. Remove password grant (OIDC Core §5.1)

- [ ] **2.1 Remove password authorization handler**
  - File: `pkg/core/service.go`
  - Remove line 160: `a.Server.SetPasswordAuthorizationHandler(passwordAuthorizationHandler)`
  - Remove the `passwordAuthorizationHandler` function (lines 171-178)

- [ ] **2.2 Verify password grant returns unsupported_grant_type**
  - When a client sends `grant_type=password` to `/oauth/token`, the library should return a 400 response with `error=unsupported_grant_type`

## 3. Fix internal error handler (RFC 6749 §5.2)

- [ ] **3.1 Change internal error handler to return error response**
  - File: `pkg/core/service.go`
  - Line 161-164: Change from:
    ```go
    a.Server.SetInternalErrorHandler(func(err error) (re *errors.Response) {
        log.Println("Internal Error:", err.Error())
        return  // ← returns nil, suppresses error
    })
    ```
    To:
    ```go
    a.Server.SetInternalErrorHandler(func(err error) (re *errors.Response) {
        log.Println("Internal Error:", err.Error())
        status, ok := errors.StatusCodes[err]
        if !ok {
            status = 400
        }
        return errors.NewResponse(err, status)  // propagate error to client
    })
    ```
  - The `go-oauth2` library uses `errors.StatusCodes` map for HTTP status codes
  - Using `errors.NewResponse(err, status)` constructs a proper RFC 6749 §5.2 response
  - This ensures token endpoint errors are emitted as RFC 6749 §5.2 compliant JSON

## 4. Enrich well-known metadata (OIDC §2)

- [ ] **4.1 Remove openid from scopes_supported**
  - File: `pkg/controllers/login.go`
  - Line 200: Change `scopes_supported` from `["openid", "profile", "email"]` to `["profile", "email"]`
  - We don't generate ID tokens, so the `openid` scope is meaningless

- [ ] **4.2 Add required metadata fields**
  - File: `pkg/controllers/login.go`
  - Add to the `config` map in `Config()` function:
    ```go
    "response_modes_supported":  []string{"query", "fragment"},
    "claims_supported":          []string{"sub", "name", "email", "email_verified"},
    "subject_types_supported":   []string{"public"},
    "token_endpoint_auth_methods_supported": []string{"client_secret_post", "basic"},
    ```

## 5. Fix /userinfo sub claim (OIDC §4.1.1.1)

- [ ] **5.1 Change sub from username to numeric ID**
  - File: `pkg/controllers/oauth.go`
  - Function: `Userinfo`
  - Current code calls `FindUserByUsername` inside the scope filtering, and uses `token.GetUserID()` for `sub`
  - Fix: Extract the user lookup before the claims map, use `fmt.Sprintf("%d", user.ID)` for `sub`:
    ```go
    user, err := models.FindUserByUsername(token.GetUserID())
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user profile"})
        return
    }

    claims := map[string]any{
        "sub": fmt.Sprintf("%d", user.ID),
    }
    scope := token.GetScope()
    if hasScope(scope, "profile") {
        claims["name"] = user.Username
    }
    if hasScope(scope, "email") && user.Email != nil {
        claims["email"] = *user.Email
        claims["email_verified"] = true
    }
    ```
  - Note: Also fix `claims["name"]` to use `user.Username` instead of `token.GetUserID()`, and guard `user.Email` with a nil check

## 6. Verify all changes

- [ ] **6.1 Run `go build ./...`**
- [ ] **6.2 Run `go vet ./...`**
- [ ] **6.3 Run `go test ./...`**
- [ ] **6.4 Verify OAuth flow: POST /oauth/authorize redirects to /login when not authenticated**
- [ ] **6.5 Verify /userinfo returns numeric sub**
- [ ] **6.6 Verify well-known metadata is complete and accurate**
- [ ] **6.7 Verify password grant returns unsupported_grant_type**
- [ ] **6.8 Verify token endpoint returns proper error codes**