package controllers

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/datastream/authservice/pkg/models"
	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-session/session/v3"
)

// OauthHandler handles the /oauth/auth endpoint
type OAuthContorller struct {
	Srv *server.Server
}

func NewOAuthController(srv *server.Server) *OAuthContorller {
	return &OAuthContorller{Srv: srv}
}

type AuthPageData struct {
	Domain  string
	AuthURL string
}

// GET /oauth/authorize
// just a simple auth page to create a post form to authorize
func AuthPage(c *gin.Context) {
	store, err := session.Start(context.TODO(), c.Writer, c.Request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// disable http cache
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")
	if _, ok := store.Get("LoggedInUserID"); !ok {
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
	err = t.Execute(c.Writer, authPageData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to render auth page"})
		return
	}
}

func (o *OAuthContorller) Login(c *gin.Context) {
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
		log.Print("Invalid credentials for user: ", user.HashedPassword, user.CheckPassword(postForm.Password), err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	store.Set("LoggedInUserID", postForm.Username)
	err = store.Save()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// handle addtional oauth flow
	if len(c.Query("client_id")) > 0 {
		// code exchage flow
		err = o.Srv.HandleAuthorizeRequest(c.Writer, c.Request)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		return
	}
	// redirect to /userinfo
	c.Header("Location", "/userinfo")
	c.JSON(http.StatusFound, gin.H{"message": "Login successful", "redirect": "/userinfo"})
}
func (o *OAuthContorller) OAuthHandler(c *gin.Context) {
	store, err := session.Start(c.Request.Context(), c.Writer, c.Request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if _, ok := store.Get("LoggedInUserID"); !ok {
		c.Header("Location", "/login")
		c.JSON(http.StatusFound, gin.H{"message": "Not logged in", "redirect": "/login"})
		return
	}
	err = o.Srv.HandleAuthorizeRequest(c.Writer, c.Request)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
}

func (o *OAuthContorller) TokenHandler(c *gin.Context) {
	err := o.Srv.HandleTokenRequest(c.Writer, c.Request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}
}

func (o *OAuthContorller) TestHandler(c *gin.Context) {
	token, err := o.Srv.ValidationBearerToken(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{
		"client_id":  token.GetClientID(),
		"user_id":    token.GetUserID(),
		"expires_in": int64(time.Until(token.GetAccessCreateAt().Add(token.GetAccessExpiresIn())).Seconds()),
		"scope":      token.GetScope(),
	})
}

// Profile shows the profile page
func (o *OAuthContorller) Userinfo(c *gin.Context) {
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
			"expires": token.GetAccessCreateAt().Add(token.GetAccessExpiresIn()).String()},
		)
		return
	}
	store, err := session.Start(context.TODO(), c.Writer, c.Request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	userID, ok := store.Get("LoggedInUserID")
	if !ok {
		c.Header("Location", "/login")
		c.JSON(http.StatusFound, gin.H{"message": "Not logged in", "redirect": "/login"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": userID})
}

type ProfileEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// ProfileEmails shows the profile email endpoint
func (o *OAuthContorller) UserinfoEmails(c *gin.Context) {
	token, err := o.Srv.ValidationBearerToken(c.Request)
	if err != nil {
		c.JSON(http.StatusNotAcceptable, gin.H{"error": err.Error()})
		return
	}
	if token != nil {
		user, err := models.FindUserByUsername(token.GetUserID())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user profile"})
			return
		}
		email := ProfileEmail{
			Email:    user.Email,
			Primary:  true,
			Verified: true,
		}
		emails := []ProfileEmail{email}
		c.JSON(http.StatusOK, emails)
		return
	}
	store, err := session.Start(context.TODO(), c.Writer, c.Request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	userID, ok := store.Get("LoggedInUserID")
	if !ok {
		c.Header("Location", "/login")
		c.JSON(http.StatusFound, gin.H{"message": "Not logged in", "redirect": "/login"})
		return
	}
	// Fetch user profile from username
	user, err := models.FindUserByUsername(userID.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user profile"})
		return
	}
	email := ProfileEmail{
		Email:    user.Email,
		Primary:  true,
		Verified: true,
	}
	emails := []ProfileEmail{email}
	c.JSON(http.StatusOK, emails)
}
