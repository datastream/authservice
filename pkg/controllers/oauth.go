package controllers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"time"

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

func (o *OAuthContorller) AuthorizeHandler(c *gin.Context) {
	store, err := session.Start(c.Request.Context(), c.Writer, c.Request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if _, ok := store.Get("LoggedInUserID"); !ok {
		store.Set("ReturnUri", c.Request.URL.RequestURI())
		store.Save()
		c.Header("Location", "/login")
		c.JSON(http.StatusFound, gin.H{"message": "Not logged in", "redirect": "/login"})
		return
	}
	err = o.Srv.HandleAuthorizeRequest(c.Writer, c.Request)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}
}

func (o *OAuthContorller) OAuthHandler(c *gin.Context) {
	store, err := session.Start(c.Request.Context(), c.Writer, c.Request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
	store.Delete("ReturnUri")
	store.Save()

	err = o.Srv.HandleAuthorizeRequest(c.Writer, c.Request)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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
