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
	UserID   string `form:"userId" json:"userId"`
}

func TokensList(c *gin.Context) {
	userID, ok, err := middleware.GetLoggedInUserID(c)
	if err != nil || !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	tokens, err := models.FindTokensByUserID(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch tokens"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"tokens": tokens,
	})
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
	if postForm.UserID == "" {
		postForm.UserID = userID
	}
	token := models.Token{
		UserID:   postForm.UserID,
		Domain:   postForm.Domain,
		Public:   postForm.Public,
		Describe: postForm.Describe,
	}
	if err := token.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":          true,
		"clientID":    token.ClientID,
		"clientSecret": token.ClientSecret,
	})
}

// TokenRevoke deletes a token owned by the logged-in user
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
