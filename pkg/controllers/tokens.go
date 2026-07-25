package controllers

import (
	"errors"
	"log"
	"net/http"

	"github.com/datastream/authservice/pkg/middleware"
	"github.com/datastream/authservice/pkg/models"
	"github.com/gin-gonic/gin"
)

type TokenForm struct {
	Domain   string `form:"domain" json:"domain" binding:"required"`
	Public   bool   `form:"public" json:"public"`
	Describe string `form:"describe" json:"describe"`
}

// TokenCreateResponse is returned only at creation time — clientSecret is never shown again.
type TokenCreateResponse struct {
	OK           bool   `json:"ok"`
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
}

// redirectOAuthAuthorize returns the OAuth authorize URL with the current
// query string, or an empty string when there is no query.
func redirectOAuthAuthorize(q string) string {
	if q != "" {
		return "/oauth/authorize?" + q
	}
	return ""
}

func TokensList(c *gin.Context) {
	userID, ok, err := middleware.GetLoggedInUserID(c)
	if err != nil || !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	rawTokens, err := models.FindTokensByUserID(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch tokens"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"tokens": rawTokens})
}

func ClientTokensCreate(c *gin.Context) {
	userID, ok, err := middleware.GetLoggedInUserID(c)
	if err != nil || !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	var postForm TokenForm
	if err := c.BindJSON(&postForm); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	token := models.Token{
		UserID:   userID,
		Domain:   postForm.Domain,
		Public:   postForm.Public,
		Describe: &postForm.Describe,
	}
	if err := token.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create token"})
		return
	}
	c.JSON(http.StatusOK, TokenCreateResponse{
		OK:           true,
		ClientID:     token.ClientID,
		ClientSecret: token.ClientSecret,
	})
}

func TokenRevoke(c *gin.Context) {
	userID, ok, err := middleware.GetLoggedInUserID(c)
	if err != nil || !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	clientID := c.Param("id")
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing token ID"})
		return
	}
	token, err := models.FindTokenByClientID(clientID)
	if errors.Is(err, models.ErrDBNotInitialized) {
		log.Println("DB error during token lookup for client:", clientID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "service unavailable"})
		return
	}
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Token not found"})
		return
	}
	if token.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Not authorized to delete this token"})
		return
	}
	if err := token.Delete(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
