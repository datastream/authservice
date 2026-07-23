package controllers

import (
	"net/http"

	"github.com/datastream/authservice/pkg/middleware"
	"github.com/datastream/authservice/pkg/models"
	"github.com/gin-gonic/gin"
)

type TokenForm struct {
	Domain   string `form:"domain" json:"domain" binding:"required"`
	Public   bool   `form:"public" json:"public"`
	Describe string `form:"describe" json:"describe"`
	UserId   string `form:"userId" json:"userId"`
}

// TokenCreateResponse is returned only at creation time — clientSecret is never shown again.
type TokenCreateResponse struct {
	OK           bool   `json:"ok"`
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
}

// TokenResponse is the JSON shape returned for single tokens.
type TokenResponse struct {
	ClientID     string  `json:"clientId"`
	ClientSecret string  `json:"clientSecret"`
	Domain       string  `json:"domain"`
	Public       bool    `json:"public"`
	Describe     *string `json:"describe"`
	UserID       string  `json:"userId"`
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
	resp := make([]TokenResponse, len(rawTokens))
	for i, t := range rawTokens {
		resp[i] = TokenResponse{
			ClientID:     t.ClientID,
			ClientSecret: t.ClientSecret,
			Domain:       t.Domain,
			Public:       t.Public,
			Describe:     t.Describe,
			UserID:       t.UserID,
		}
	}
	c.JSON(http.StatusOK, gin.H{"tokens": resp})
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
	// Allow creating tokens for another user if userId is provided.
	targetUserID := userID
	if postForm.UserId != "" {
		targetUserID = postForm.UserId
	}
	token := models.Token{
		UserID:   targetUserID,
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
