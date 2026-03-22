package controllers

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

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

// GET /oauth/authorize (unchanged)
// just a simple auth page to create a post form to authorize
func AuthPage(c *gin.Context) {
	// Retrieve login status via middleware (userID not needed here)
	_, ok, err := middleware.GetLoggedInUserID(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// disable http cache
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")
	if !ok {
		c.Header("Location", fmt.Sprintf("/login?%s", c.Request.URL.RawQuery))
		c.JSON(http.StatusFound, gin.H{"message": "Not logged in", "redirect": fmt.Sprintf("/login?%s", c.Request.URL.RawQuery)})
		return
	}
	authPageData := AuthPageData{
		AuthURL: c.Request.RequestURI,
		Domain:  c.Request.Host,
	}
	token, err := models.FindTokenByClientID(c.Query("client_id"))
	if err != nil {
		c.Header("Location", "/userinfo")
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
	store, err := session.Start(c.Request.Context(), c.Writer, c.Request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// check user password
	user, err := models.FindUserByUsername(postForm.Username)
	if err != nil || user.CheckPassword(postForm.Password) != nil {
		log.Println("Invalid credentials for user:", postForm.Username, err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	store.Set("LoggedInUserID", postForm.Username)
	if err = store.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// handle additional oauth flow
	if len(c.Query("client_id")) > 0 {
		// code exchange flow
		if err = o.Srv.HandleAuthorizeRequest(c.Writer, c.Request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		return
	}
	// redirect to /userinfo
	c.Header("Location", "/userinfo")
	c.JSON(http.StatusFound, gin.H{"message": "Login successful", "redirect": "/userinfo"})
}

func (o *OAuthController) OAuthHandler(c *gin.Context) {
	// Retrieve login status via middleware (userID not needed here)
	_, ok, err := middleware.GetLoggedInUserID(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !ok {
		c.Header("Location", "/login")
		c.JSON(http.StatusFound, gin.H{"message": "Not logged in", "redirect": "/login"})
		return
	}
	// Proceed with OAuth authorization request
	if err = o.Srv.HandleAuthorizeRequest(c.Writer, c.Request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
}

func (o *OAuthController) TokenHandler(c *gin.Context) {
	if err := o.Srv.HandleTokenRequest(c.Writer, c.Request); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}
}

func (o *OAuthController) TestHandler(c *gin.Context) {
	token, err := o.Srv.ValidationBearerToken(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"client_id":  token.GetClientID(),
		"user_id":    token.GetUserID(),
		"expires_in": int64(time.Until(token.GetAccessCreateAt().Add(token.GetAccessExpiresIn())).Seconds()),
		"scope":      token.GetScope(),
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
		c.JSON(http.StatusOK, gin.H{
			"sub":     token.GetUserID(),
			"name":    token.GetUserID(),
			"login":   token.GetUserID(),
			"client":  token.GetClientID(),
			"email":   user.Email,
			"expires": token.GetAccessCreateAt().Add(token.GetAccessExpiresIn()).String(),
		})
		return
	}
	// No valid token and no session fallback: unauthorized
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
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	if token != nil {
		user, err := models.FindUserByUsername(token.GetUserID())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user profile"})
			return
		}
		email := ProfileEmail{Email: user.Email, Primary: true, Verified: true}
		c.JSON(http.StatusOK, []ProfileEmail{email})
		return
	}
	// No valid token and no session fallback: unauthorized
	c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or missing access token"})
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
