// Package controllers provides HTTP handlers for the OAuth service using the Gin framework.
// It includes controllers for login, OAuth authorization, token management, and FGA integration.
package controllers

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
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

type AuthPageData struct {
	Domain  string
	AuthURL string
}

// GET /oauth/authorize renders the OAuth consent page.
// For SPA-aware clients (JSON accept), it redirects to /login if not authenticated.
// For browser clients, it renders the Go consent template with session data.
func AuthPage(c *gin.Context) {
	// Check session first
	_, ok, err := middleware.GetLoggedInUserID(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !ok {
		// Not logged in - redirect to /login with preserved query params
		query := c.Request.URL.RawQuery
		if query != "" {
			c.Redirect(http.StatusFound, "/login?"+query)
		} else {
			c.Redirect(http.StatusFound, "/login")
		}
		return
	}
	// disable http cache
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")

	// Restore ReturnUri form data if present (from login redirect)
	if v, exists := c.Get("ReturnUri"); exists {
		if serialized, ok := v.(string); ok {
			c.Request.ParseForm()
			if err = json.Unmarshal([]byte(serialized), &c.Request.Form); err != nil {
				log.Printf("failed to restore ReturnUri: %v", err)
			}
		}
	}

	authPageData := AuthPageData{
		AuthURL: c.Request.RequestURI,
		Domain:  c.Request.Host,
	}
	token, err := models.FindTokenByClientID(c.Query("client_id"))
	if err != nil {
		c.JSON(http.StatusFound, gin.H{"message": "Client not found", "redirect": "/userinfo"})
		return
	}
	authPageData.Domain = token.Domain

	// render auth page
	t, err := template.ParseFiles("static/auth.html")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load auth page"})
		return
	}
	if err = t.Execute(c.Writer, authPageData); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to render auth page"})
		return
	}
}

func (o *OAuthController) Login(c *gin.Context) {
	var postForm LoginForm
	if err := c.ShouldBind(&postForm); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	oldStore, err := session.Start(c.Request.Context(), c.Writer, c.Request)
	if err != nil {
		middleware.Fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	// check user password
	user, err := models.FindUserByUsername(postForm.Username)
	if err != nil || user.CheckPassword(postForm.Password) != nil {
		log.Println("Invalid credentials for user:", postForm.Username, err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	oldStore.Flush()
	if err = oldStore.Save(); err != nil {
		middleware.Fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	newStore, err := session.Start(c.Request.Context(), c.Writer, c.Request)
	if err != nil {
		middleware.Fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	newStore.Set("LoggedInUserID", postForm.Username)
	if err = newStore.Save(); err != nil {
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
	// Session check is already done by AuthPage (GET). The go-oauth2 library's
	// HandleAuthorizeRequest internally calls userAuthorizeHandler which checks
	// the session. We delegate to it directly.
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

func (o *OAuthController) TestHandler(c *gin.Context) {
	token, err := o.Srv.ValidationBearerToken(c.Request)
	if err != nil {
		// RFC 7662 §2.1: introspection endpoint always returns 200
		c.JSON(http.StatusOK, gin.H{
			"active": false,
		})
		return
	}

	createdAt := token.GetAccessCreateAt()
	expiresIn := token.GetAccessExpiresIn()
	c.JSON(http.StatusOK, gin.H{
		"active":    true,
		"scope":     token.GetScope(),
		"client_id": token.GetClientID(),
		"user":      token.GetUserID(),
		"iat":       createdAt.Unix(),
		"exp":       createdAt.Add(expiresIn).Unix(),
	})
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
	email := ProfileEmail{Email: user.Email, Primary: true, Verified: true}
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
	// Per RFC 7678 §2.2: server MUST NOT reveal whether token existed
	_ = err
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
			c.Set("Subject", user)
		}
		c.Next()
	}
}
