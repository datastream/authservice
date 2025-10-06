package controllers

import (
	"net/http"

	"github.com/datastream/authservice/pkg/models"
	"github.com/gin-gonic/gin"
)

type RegisterForm struct {
	Username string `form:"username" json:"username" binding:"required"`
	Email    string `form:"email" json:"email" binding:"required,email"`
	Password string `form:"password" binding:"required"`
}

func NewUser(c *gin.Context) {
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

	http.ServeContent(c.Writer, c.Request, "register.html", stat.ModTime(), loginPage)
}
func Register(c *gin.Context) {
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

	c.JSON(http.StatusOK, gin.H{"message": "Register successful"})
}
