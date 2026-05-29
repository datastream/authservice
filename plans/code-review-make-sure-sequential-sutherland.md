# Implementation Plan: OAuth 2.0 Full Compliance

## Context

Implements P0-P2 findings from the OAuth 2.0 compliance audit. Fixes 10 issues across RFC 6749, 7662, 7678, 7667, and RFC 8414. A prior change (`fix-oauth2-compliance`) already addressed state parameter, CORS headers, basic OpenID metadata, consent bypass, and introspection response shape.

**Files to modify**: 6 files

---

## Step 1: Fix redirect URI validation + disable implicit flow

**File**: `pkg/core/service.go`

### 1A. Override redirect URI validation (Finding #2)

In `InitOAuthServer()`, after `manager := manage.NewDefaultManager()`, add exact host matching:

```go
import "net/url"

// Override default domain-suffix matching with exact host matching
manager.SetValidateURIHandler(func(baseURI, redirectURI string) error {
    base, err := url.Parse(baseURI)
    if err != nil {
        return errors.ErrInvalidRedirectURI
    }
    redirect, err := url.Parse(redirectURI)
    if err != nil {
        return errors.ErrInvalidRedirectURI
    }
    // Exact host match (not domain-suffix).
    // Client registered with "example.com" → only example.com sub-paths allowed.
    // "evil.example.com/callback" is REJECTED.
    if redirect.Host != base.Host {
        return errors.ErrInvalidRedirectURI
    }
    return nil
})
```

**Import note**: `errors` here refers to `github.com/go-oauth2/oauth2/v4/errors`. Add to imports.

### 1B. Disable implicit response type (Finding #1)

In `SetServerHandlers()`, after server config setup, add:

```go
srv.SetAllowedResponseType(oauth2.Code)
```

This restricts the server to only accept `response_type=code`. The library defaults to allowing both `code` and `token` (implicit flow). Explicitly setting this prevents accidental implicit flow usage.

Need to import `oauth2 "github.com/go-oauth2/oauth2/v4"` for the `oauth2.Code` constant.

---

## Step 2: Fix OpenID metadata + client auth methods

**File**: `pkg/controllers/login.go`

Update the `Config()` function (lines 237-255):

```go
func Config(c *gin.Context) {
    schema := c.Request.Header.Get("X-Forwarded-Proto")
    if schema == "" {
        schema = c.Request.URL.Scheme
    }
    if schema == "" {
        schema = "http"
    }
    issuer := fmt.Sprintf("%s://%s", schema, c.Request.Host)
    config := map[string]interface{}{
        "issuer":                             issuer,
        "authorization_endpoint":             issuer + "/oauth/authorize",
        "token_endpoint":                     issuer + "/oauth/token",
        "token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
        "code_challenge_methods_supported":     []string{"S256"},
        "scopes_supported":                   []string{"openid", "profile", "email"},
        "response_types_supported":             []string{"code"},
    }
    c.JSON(http.StatusOK, config)
}
```

Changes:
- Remove `"code token"` — keep only `"code"` (Finding #1)
- Add `token_endpoint_auth_methods_supported` — REQUIRED by RFC 8414 §3
- Add `code_challenge_methods_supported` — SHOULD by RFC 7636 §4
- Remove `userinfo_endpoint` — server doesn't implement full OIDC UserInfo

---

## Step 3: Add combined client auth handler

**File**: `pkg/core/service.go`

Replace the existing `SetClientInfoHandler` call in `SetServerHandlers()`:

**Current** (line 127):
```go
a.Server.SetClientInfoHandler(server.ClientFormHandler)
```

**New**:
```go
a.Server.SetClientInfoHandler(func(r *http.Request) (string, string, error) {
    // Try Basic Auth first (more secure — secrets not in request body/logs)
    if clientID, secret, ok := r.BasicAuth(); ok {
        return clientID, secret, nil
    }
    // Fall back to form body (backward compatibility)
    return server.ClientFormHandler(r)
})
```

This accepts both `Authorization: Basic ...` and `client_id`/`client_secret` form params (Finding #6).

---

## Step 4: Add token revocation endpoint

**Files**: `pkg/controllers/oauth.go`, `cmd/oauthservice/main.go`

### Handler in `pkg/controllers/oauth.go`

```go
func (o *OAuthController) RevokeToken(c *gin.Context) {
    token := c.PostForm("token")
    if token == "" {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "missing token",
        })
        return
    }
    hint := c.PostForm("token_type_hint")
    // Remove the token
    ctx := c.Request.Context()
    var err error
    switch hint {
    case "refresh_token":
        err = o.Srv.Manager.RemoveRefreshToken(ctx, token)
    default:
        err = o.Srv.Manager.RemoveAccessToken(ctx, token)
    }
    // Per RFC 7678 §2.2: server MUST NOT reveal whether token existed
    _ = err
    c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
```

**Note**: `o.Srv.Manager` accesses the library's Manager for token removal. The Manager has `RemoveAccessToken` and `RemoveRefreshToken` methods.

### Route in `cmd/oauthservice/main.go`

Add after the other OAuth routes (around line 91):
```go
r.POST("/oauth/revoke", oauth.RevokeToken)
```

---

## Step 5: Scope-filter /userinfo claims

**File**: `pkg/controllers/oauth.go`

### 5A. Userinfo handler

```go
func (o *OAuthController) Userinfo(c *gin.Context) {
    token, err := o.Srv.ValidationBearerToken(c.Request)
    if err == nil && token != nil {
        user, err := models.FindUserByUsername(token.GetUserID())
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user profile"})
            return
        }
        
        claims := map[string]interface{}{
            "sub": token.GetUserID(),
        }
        
        scope := token.GetScope()
        if strings.Contains(scope, "profile") {
            claims["name"] = token.GetUserID()
        }
        if strings.Contains(scope, "email") {
            claims["email"] = user.Email
            claims["email_verified"] = true
        }
        
        c.JSON(http.StatusOK, claims)
        return
    }
    c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or missing access token"})
}
```

Key changes:
- Start with `sub` only (required for `openid` scope)
- Add `name` only if `profile` scope present
- Add `email` + `email_verified` only if `email` scope present
- Remove non-standard `login`, `client`, `expires` claims (Finding #10)
- Use `strings.Contains` for space-separated scope matching (OAuth 2.0 scopes are space-separated)

### 5B. UserinfoEmails handler

```go
func (o *OAuthController) UserinfoEmails(c *gin.Context) {
    token, err := o.Srv.ValidationBearerToken(c.Request)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or missing access token"})
        return
    }
    if token != nil {
        // Scope check: email scope required
        if !strings.Contains(token.GetScope(), "email") {
            c.JSON(http.StatusForbidden, gin.H{"error": "email scope required"})
            return
        }
        user, err := models.FindUserByUsername(token.GetUserID())
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user profile"})
            return
        }
        email := ProfileEmail{Email: user.Email, Primary: true, Verified: true}
        c.JSON(http.StatusOK, []ProfileEmail{email})
        return
    }
    c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or missing access token"})
}
```

Key changes:
- Fix error message to be generic (Finding #7)
- Add scope check for `email`
- Always return consistent error format

### 5C. Add `strings` import

Both handlers need `strings` for `strings.Contains(scope, "profile")` matching.

---

## Step 6: Remove password grant handler

**File**: `pkg/core/service.go`

Remove the `SetPasswordAuthorizationHandler` block (lines 129-139):

```go
// REMOVED:
a.Server.SetPasswordAuthorizationHandler(func(ctx context.Context, clientID, username, password string) (userID string, err error) {
    user, err := models.FindUserByUsername(username)
    if err != nil || user.CheckPassword(password) != nil {
        log.Println("Invalid credentials for user: ", username, err)
        err = errors.New("invalid username or password")
        return
    }
    userID = user.Username
    return
})
```

This removes `grant_type=password` support. If needed later, gate behind a config flag.

---

## Step 7: Update testutils

**File**: `testutils/helpers.go`

Add the `/oauth/revoke` route to the test router setup (around line 77):
```go
r.POST("/oauth/revoke", oauth.RevokeToken)
```

---

## Verification

1. Run `go build ./...` to check compilation
2. Run `go vet ./...` for static analysis
3. Run `go test ./...` to verify tests pass
4. Test manual flows:
   - Authorization code grant with `response_type=code` (should work)
   - `response_type=token` (should be rejected)
   - `response_type=code token` (should be rejected)
   - Client auth via Basic Auth header
   - Client auth via form body (backward compat)
   - Redirect to `https://different-host.com/callback` (should be rejected)
   - `/userinfo` with `scope=openid` (should return only `sub`)
   - `/userinfo` with `scope=openid email` (should return `sub` + `email`)
   - `POST /oauth/revoke` with valid token
   - `POST /oauth/revoke` with invalid token (should return 200)
   - `GET /.well-known/openid-configuration` (should have correct fields)

---

## File Summary

| File | Changes |
|------|---------|
| `pkg/core/service.go` | Redirect URI validation override, remove password grant, disable implicit flow, combined client auth |
| `pkg/controllers/login.go` | Fix OIDC metadata, add auth methods + PKCE fields |
| `pkg/controllers/oauth.go` | Revocation endpoint, scope-filter userinfo, fix error messages |
| `cmd/oauthservice/main.go` | Add `/oauth/revoke` route |
| `testutils/helpers.go` | Add revocation route to test router |
