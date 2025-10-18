package controllers

import (
	"context"
	"log"
	"net/http"

	"github.com/datastream/authservice/pkg/models"
	"github.com/gin-gonic/gin"
	"github.com/go-session/session/v3"
)

type LoginForm struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" binding:"required"`
}

// login page don't need to handle uri query params
func LoginPage(c *gin.Context) {
	store, err := session.Start(context.TODO(), c.Writer, c.Request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if _, ok := store.Get("LoggedInUserID"); ok {
		// redirect to redirect url or /profile
		if uri, ok := store.Get("ReturnUri"); ok {
			c.Header("Location", uri.(string))
			c.JSON(http.StatusTemporaryRedirect, gin.H{"message": "Login successful", "redirect": uri.(string)})
			return
		}
		c.Header("Location", "/profile")
		c.JSON(http.StatusFound, gin.H{"message": "Logged in", "redirect": "/auth"})
		return
	}

	loginPage, err := http.Dir("static").Open("login.html")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load login page"})
		return
	}
	defer loginPage.Close()

	stat, err := loginPage.Stat()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read login page"})
		return
	}

	http.ServeContent(c.Writer, c.Request, "login.html", stat.ModTime(), loginPage)
}

func Login(c *gin.Context) {
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
	if uri, ok := store.Get("ReturnUri"); ok {
		c.Header("Location", uri.(string))
		c.JSON(http.StatusFound, gin.H{"message": "Login successful", "redirect": uri.(string)})
		return
	}
	c.Header("Location", "/profile")
	c.JSON(http.StatusFound, gin.H{"message": "Login successful", "redirect": "/profile"})
}

func Logout(c *gin.Context) {
	store, err := session.Start(c.Request.Context(), c.Writer, c.Request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	store.Flush()
	err = store.Save()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// redirect to /login
	c.Header("Location", "/login")
	c.JSON(http.StatusFound, gin.H{"message": "Logout successful", "redirect": "/login"})
}
