package controllers

import (
	"log"
	"net/http"

	"github.com/datastream/authservice/pkg/middleware"
	"github.com/datastream/authservice/pkg/models"
	"github.com/gin-gonic/gin"
	"github.com/go-session/session/v3"
)

// restartSession resets the session to prevent session fixation attacks.
// The setFn callback configures the new session store before it is saved.
func restartSession(c *gin.Context, setFn func(store session.Store)) error {
	oldStore, err := session.Start(c.Request.Context(), c.Writer, c.Request)
	if err != nil {
		return err
	}
	oldStore.Flush()
	if err = oldStore.Save(); err != nil {
		return err
	}
	newStore, err := session.Start(c.Request.Context(), c.Writer, c.Request)
	if err != nil {
		return err
	}
	setFn(newStore)
	return newStore.Save()
}

// LoginAPI handles POST /api/login for SPA-based login.
func LoginAPI(c *gin.Context) {
	var postForm LoginForm
	if err := c.ShouldBind(&postForm); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username and password are required"})
		return
	}

	user, err := models.FindUserByUsername(postForm.Username)
	if err != nil || user.CheckPassword(postForm.Password) != nil {
		log.Println("Invalid credentials for user:", postForm.Username, err)
		middleware.RecordLoginFailure(postForm.Username)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if err := restartSession(c, func(s session.Store) {
		s.Set("LoggedInUserID", postForm.Username)
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "session error: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// SignupAPI handles POST /api/signup for SPA-based user registration.
func SignupAPI(c *gin.Context) {
	var postForm RegisterForm
	if err := c.ShouldBind(&postForm); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user := models.NewUser(postForm.Username, postForm.Email)
	user.GenHashedPassword(postForm.Password)
	if err := user.Save(); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		return
	}

	if err := restartSession(c, func(s session.Store) {
		s.Set("LoggedInUserID", postForm.Username)
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "session error: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// LogoutAPI handles POST /api/logout for SPA-based logout.
func LogoutAPI(c *gin.Context) {
	store, err := session.Start(c.Request.Context(), c.Writer, c.Request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "session error: " + err.Error()})
		return
	}
	store.Flush()
	if err = store.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "session error: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// MeAPI handles GET /api/me to check current authentication state.
func MeAPI(c *gin.Context) {
	userID, ok, err := middleware.GetLoggedInUserID(c)
	if err != nil || !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"username": userID})
}
