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

func LoginPage(c *gin.Context) {
	store, err := session.Start(context.TODO(), c.Writer, c.Request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if _, ok := store.Get("LoggedInUserID"); ok {
		if c.Request.URL.RawQuery != "" {
			c.Header("Location", "/auth?"+c.Request.URL.RawQuery)
			c.JSON(http.StatusFound, gin.H{"message": "Logged in", "redirect": "/auth?" + c.Request.URL.RawQuery})
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
	// redirect to redirect url or /profile
	if uri, ok := store.Get("ReturnUri"); ok {
		if url, ok := uri.(string); ok && url != "" {
			store.Delete("ReturnUri")
			store.Save()
			c.Header("Location", url)
			c.JSON(http.StatusFound, gin.H{"message": "Login successful", "redirect": url})
			return
		}
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
	store.Delete("LoggedInUserID")
	err = store.Save()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// redirect to /login
	c.Header("Location", "/login")
	c.JSON(http.StatusFound, gin.H{"message": "Logout successful", "redirect": "/login"})
}

// AuthHandler handles the /auth endpoint
// /login?xxx -> /auth?xxx if logged in
func AuthHandler(c *gin.Context) {
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
	c.Request.ParseForm()
	if c.Request.Form != nil {
		// save raw query to session
		store.Set("AuthForm", c.Request.Form)
		store.Save()
	}
	// need to work on auth.html, pass url's query params to form
	authPage, err := http.Dir("static").Open("auth.html")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load auth page"})
		return
	}
	defer authPage.Close()
	stat, err := authPage.Stat()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read auth page"})
		return
	}
	http.ServeContent(c.Writer, c.Request, "auth.html", stat.ModTime(), authPage)
}
