package controllers

import (
	"net/http"

	"github.com/datastream/authservice/pkg/middleware"
	"github.com/datastream/authservice/pkg/models"
	"github.com/gin-gonic/gin"
	"github.com/go-session/session/v3"
)

type RegisterForm struct {
	Username string `form:"username" json:"username" binding:"required"`
	Email    string `form:"email" json:"email" binding:"required,email"`
	Password string `form:"password" binding:"required"`
}

// NewUser serves the signup page.
func NewUser(c *gin.Context) {
	if err := middleware.ServeStaticHTML(c, "signup.html"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load signup page"})
		return
	}
}

// Signup registers a new user and logs them in.
func Signup(c *gin.Context) {
	var postForm RegisterForm
	if err := c.ShouldBind(&postForm); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	user := models.User{
		Username: postForm.Username,
		Email:    postForm.Email,
	}
	user.GenHashedPassword(postForm.Password)
	if err := user.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
		return
	}
	oldStore, err := session.Start(c.Request.Context(), c.Writer, c.Request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	oldStore.Flush()
	if err = oldStore.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	newStore, err := session.Start(c.Request.Context(), c.Writer, c.Request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	newStore.Set("LoggedInUserID", postForm.Username)
	if err = newStore.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// redirect to /auth
	c.Header("Location", "/auth")
	c.JSON(http.StatusFound, gin.H{"message": "Registration successful", "redirect": "/auth"})
}
