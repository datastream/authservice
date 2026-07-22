// Package controllers provides HTTP handlers for the OAuth service using the Gin framework.
// It includes controllers for login, OAuth authorization, token management, and FGA integration.
package controllers

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/datastream/authservice/pkg/middleware"
	"github.com/datastream/authservice/pkg/models"
	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-session/session/v3"
)

// OAuthHandler handles the /oauth/auth endpoint
type OAuthController struct {
	Srv *server.Server
}

func NewOAuthController(srv *server.Server) *OAuthController {
	return &OAuthController{Srv: srv}
}

// AuthorizeApprove is a JSON API endpoint for programmatic consent approval.
// Used by the Vue SPA and mobile apps to approve OAuth authorization requests.
func (o *OAuthController) AuthorizeApprove(c *gin.Context) {
	// Validate required parameters
	clientID := c.PostForm("client_id")
	redirectURI := c.PostForm("redirect_uri")
	state := c.PostForm("state")
	codeChallenge := c.PostForm("code_challenge")
	codeChallengeMethod := c.PostForm("code_challenge_method")

	if clientID == "" || redirectURI == "" || state == "" || codeChallenge == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid_request",
		})
		return
	}
	if codeChallengeMethod != "S256" && codeChallengeMethod != "plain" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid_request",
		})
		return
	}

	// Verify client exists and user owns it
	token, err := models.FindTokenByClientID(clientID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "unauthorized_client",
		})
		return
	}
	userID, ok, err := middleware.GetLoggedInUserID(c)
	if err != nil || !ok || userID != token.UserID {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "forbidden",
		})
		return
	}

	// Build the authorization request as form data for the library
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("redirect_uri", redirectURI)
	form.Set("response_type", "code")
	form.Set("state", state)
	form.Set("code_challenge", codeChallenge)
	form.Set("code_challenge_method", codeChallengeMethod)
	if scope := c.PostForm("scope"); scope != "" {
		form.Set("scope", scope)
	}

	// Create a request that the library can process
	body := bytes.NewBufferString(form.Encode())
	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodPost, "/oauth/authorize", body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", body.Len()))

	// Delegate to the library to generate the authorization code
	if err := o.Srv.HandleAuthorizeRequest(c.Writer, req); err != nil {
		log.Printf("AuthorizeApprove: HandleAuthorizeRequest failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
	}
}

func (o *OAuthController) Login(c *gin.Context) {
	var postForm LoginForm
	if err := c.ShouldBind(&postForm); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	store, err := session.Start(c.Request.Context(), c.Writer, c.Request)
	if err != nil {
		middleware.Fail(c, http.StatusInternalServerError, err.Error())
		return
	}

	// check user password
	user, err := models.FindUserByUsername(postForm.Username)
	if err != nil || user.CheckPassword(postForm.Password) != nil {
		log.Println("Invalid credentials for user:", postForm.Username, err)
		middleware.RecordLoginFailure(postForm.Username)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Regenerate session to prevent session fixation
	store.Flush()
	if err = store.Save(); err != nil {
		middleware.Fail(c, http.StatusInternalServerError, err.Error())
		return
	}

	if query := c.Request.URL.RawQuery; len(query) > 0 {
		c.JSON(http.StatusOK, gin.H{
			"message":  "Login successful",
			"redirect": "/oauth/authorize?" + query,
		})
	} else {
		c.JSON(http.StatusOK, gin.H{"message": "Login successful", "redirect": "/userinfo"})
	}
}

func (o *OAuthController) OAuthHandler(c *gin.Context) {
	// Explicit session check for defense-in-depth.
	// The go-oauth2 library also checks the session internally via userAuthorizeHandler,
	// but we check here first so we return a consistent JSON error instead of
	// relying on the library's error formatting.
	_, ok, err := middleware.GetLoggedInUserID(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		c.Abort()
		return
	}

	if err := o.Srv.HandleAuthorizeRequest(c.Writer, c.Request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
}

func (o *OAuthController) TokenHandler(c *gin.Context) {
	if err := o.Srv.HandleTokenRequest(c.Writer, c.Request); err != nil {
		middleware.Fail(c, http.StatusInternalServerError, err.Error())
	}
}

// Profile shows the profile page
func (o *OAuthController) Userinfo(c *gin.Context) {
	token, err := o.Srv.ValidationBearerToken(c.Request)
	if err == nil && token != nil {
		user, err := models.FindUserByUsername(token.GetUserID())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user profile"})
			return
		}

		// Scope-based claim filtering per OIDC Core §5.1
		claims := map[string]any{
			"sub": token.GetUserID(),
		}
		scope := token.GetScope()
		if hasScope(scope, "profile") {
			claims["name"] = token.GetUserID()
		}
		if hasScope(scope, "email") {
			claims["email"] = user.Email
			claims["email_verified"] = true
		}

		c.JSON(http.StatusOK, claims)
		return
	}
	c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or missing access token"})
}

type ProfileEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// ProfileEmails shows the profile email endpoint
func (o *OAuthController) UserinfoEmails(c *gin.Context) {
	token, err := o.Srv.ValidationBearerToken(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or missing access token"})
		return
	}
	// email scope required for this endpoint
	if !hasScope(token.GetScope(), "email") {
		c.JSON(http.StatusForbidden, gin.H{"error": "email scope required"})
		return
	}
	user, err := models.FindUserByUsername(token.GetUserID())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user profile"})
		return
	}
	email := ProfileEmail{Email: *user.Email, Primary: true, Verified: true}
	c.JSON(http.StatusOK, []ProfileEmail{email})
}

// RevokeToken implements RFC 7678 token revocation.
func (o *OAuthController) RevokeToken(c *gin.Context) {
	token := c.PostForm("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing token"})
		return
	}
	hint := c.PostForm("token_type_hint")
	ctx := c.Request.Context()
	var err error
	switch hint {
	case "refresh_token":
		err = o.Srv.Manager.RemoveRefreshToken(ctx, token)
	default:
		err = o.Srv.Manager.RemoveAccessToken(ctx, token)
	}
	// Per RFC 7678 §2.2: return 200 regardless of whether the token existed
	// (don't leak existence). But return 500 if the token store itself failed.
	if err != nil {
		log.Printf("RevokeToken: store error removing token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token revocation failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// hasScope checks if a space-delimited scope string contains the exact target scope.
// OAuth 2.0 scopes are space-separated; "offline_access" must not match "email".
func hasScope(scope, target string) bool {
	for s := range strings.FieldsSeq(scope) {
		if s == target {
			return true
		}
	}
	return false
}

func (o *OAuthController) OAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := o.Srv.ValidationBearerToken(c.Request)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or missing access token"})
			c.Abort()
			return
		}
		if token != nil {
			user, err := models.FindUserByUsername(token.GetUserID())
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user profile"})
				return
			}
			c.Set("Subject", user.Username)
		}
		c.Next()
	}
}