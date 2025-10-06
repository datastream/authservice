package controllers

import (
	"context"
	"net/http"

	"github.com/datastream/authservice/pkg/models"
	"github.com/gin-gonic/gin"
	"github.com/go-session/session/v3"
)

// ClientTokensShow shows the tokens page
func ClientTokensShow(c *gin.Context) {
	store, err := session.Start(context.TODO(), c.Writer, c.Request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if _, ok := store.Get("LoggedInUserID"); !ok {
		c.Header("Location", "/login")
		c.JSON(http.StatusFound, gin.H{"message": "Not logged in", "redirect": "/login"})
		return
	}
	tokenPage, err := http.Dir("static").Open("tokens.html")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load tokens page"})
		return
	}
	defer tokenPage.Close()
	stat, err := tokenPage.Stat()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read tokens page"})
		return
	}
	http.ServeContent(c.Writer, c.Request, "tokens.html", stat.ModTime(), tokenPage)
}

type TokenForm struct {
	Domain   string `form:"domain" json:"domain" binding:"required"`
	Public   bool   `form:"public" json:"public" binding:"required"`
	Describe string `form:"describe" json:"describe"`
	UserID   string `form:"userId" json:"userID" binding:"required"`
}

func ClientTokensCreate(c *gin.Context) {
	store, err := session.Start(context.TODO(), c.Writer, c.Request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if _, ok := store.Get("LoggedInUserID"); !ok {
		c.Header("Location", "/login")
		c.JSON(http.StatusFound, gin.H{"message": "Not logged in", "redirect": "/login"})
		return
	}
	var postForm TokenForm
	if err := c.ShouldBind(&postForm); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
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
