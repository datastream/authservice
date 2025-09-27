package controllers

import (
	"context"
	"net/http"

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
func ClientTokensCreate(c *gin.Context) {
}
