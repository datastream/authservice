package controllers

import (
	"net/http"

	"github.com/datastream/authservice/pkg/models"
	"github.com/gin-gonic/gin"
	"github.com/go-session/session/v3"
)

type RegisterForm struct {
	Username string `form:"username" json:"username" binding:"required"`
	Email    string `form:"email" json:"email" binding:"required,email"`
	Password string `form:"password" binding:"required"`
}

func NewUser(c *gin.Context) {
	signupPage, err := http.Dir("static").Open("signup.html")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load signup page"})
		return
	}
	defer signupPage.Close()

	stat, err := signupPage.Stat()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read signup page"})
		return
	}

	http.ServeContent(c.Writer, c.Request, "signup.html", stat.ModTime(), signupPage)
}
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
	user.BeforeSave(postForm.Password)
	if err := user.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
	}
	store, err := session.Start(c.Request.Context(), c.Writer, c.Request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	store.Set("LoggedInUserID", postForm.Username)
	err = store.Save()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// redirect to /auth
	c.Header("Location", "/auth")
	c.JSON(http.StatusFound, gin.H{"message": "Login successful", "redirect": "/auth"})
}
