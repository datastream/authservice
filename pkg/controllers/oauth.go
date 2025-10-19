package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
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
	// save raw query to session
	c.Request.ParseForm()
	if len(c.Request.Form) > 0 {
		store.Set("AuthForm", c.Request.Form)
		store.Save()
	}
	token, err := models.FindTokenByClientID(c.Request.Form.Get("client_id"))
	if err != nil {
		c.Header("Location", "/profile")
		c.JSON(http.StatusFound, gin.H{"message": "Client not found", "redirect": "/profile"})
		return
	}

	// render auth page
	t, err := template.ParseFiles("static/auth.html")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load auth page"})
		return
	}
	err = t.Execute(c.Writer, token.Domain)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to render auth page"})
		return
	}
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
	var form url.Values
	if v, ok := store.Get("AuthForm"); ok {
		// set v to request form
		payload, err := json.Marshal(v)
		if err == nil {
			err = json.Unmarshal(payload, &form)
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}
	c.Request.Form = form

	err = o.Srv.HandleAuthorizeRequest(c.Writer, c.Request)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	store.Delete("AuthForm")
	store.Save()
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
func (o *OAuthContorller) Profile(c *gin.Context) {
	token, err := o.Srv.ValidationBearerToken(c.Request)
	if err == nil && token != nil {
		c.JSON(http.StatusOK, gin.H{"user": token.GetUserID(), "client": token.GetClientID(), "expires": token.GetAccessCreateAt().Add(token.GetAccessExpiresIn()).String()})
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
