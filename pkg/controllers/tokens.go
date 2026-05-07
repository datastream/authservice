package controllers

import (
	"net/http"

	"github.com/datastream/authservice/pkg/middleware"
	"github.com/datastream/authservice/pkg/models"
	"github.com/gin-gonic/gin"
)

// Managerpage shows the tokens page
func Managerpage(c *gin.Context) {
	userID := middleware.RequireLogin(c)
	if userID == "" {
		return
	}
	if err := middleware.ServeStaticHTML(c, "tokens.html"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load tokens page"})
		return
	}
}

type TokenForm struct {
	Domain   string `form:"domain" json:"domain" binding:"required"`
	Public   bool   `form:"public" json:"public"`
	Describe string `form:"describe" json:"describe"`
	UserID   string `form:"userId" json:"userId"`
}

func ClientTokensCreate(c *gin.Context) {
	userID := middleware.RequireLogin(c)
	if userID == "" {
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
		"message":       "Token created successfully",
		"client_id":     token.ClientID,
		"client_secret": token.ClientSecret,
	})
}
func TokensList(c *gin.Context) {
	userID := middleware.RequireLogin(c)
	if userID == "" {
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

// TokenRevoke deletes a token owned by the logged-in user
func TokenRevoke(c *gin.Context) {
	userID := middleware.RequireLogin(c)
	if userID == "" {
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
	c.JSON(http.StatusOK, gin.H{"message": "Token revoked successfully"})
}
