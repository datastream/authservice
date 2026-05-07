// Package middleware provides Gin middleware and utility helpers for session
// management, JSON error responses, and static HTML serving.
package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-session/session/v3"
	"log"
)

// GetLoggedInUserID starts a session and returns the logged‑in user ID.
// It returns the user ID, a bool indicating if the ID was present, and any error that occurred while starting the session.
func GetLoggedInUserID(c *gin.Context) (string, bool, error) {
	// Use the request context to start the session.
	store, err := session.Start(c.Request.Context(), c.Writer, c.Request)
	if err != nil {
		// Log and return the error; callers can use JSONError to report to the client.
		log.Print("session start error: ", err)
		return "", false, err
	}
	// Retrieve the user ID from the session.
	userIDRaw, ok := store.Get("LoggedInUserID")
	if !ok {
		return "", false, nil
	}
	// The stored value should be a string.
	userID, ok := userIDRaw.(string)
	if !ok {
		return "", false, nil
	}
	return userID, true, nil
}

// RequireLogin starts a session, extracts the logged-in user ID, and aborts
// the handler with a 302 redirect to /login if the user is not authenticated.
// It returns the user ID string on success.
func RequireLogin(c *gin.Context) string {
	store, err := session.Start(c.Request.Context(), c.Writer, c.Request)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return ""
	}

	userIDRaw, ok := store.Get("LoggedInUserID")
	if !ok {
		c.Header("Location", "/login")
		c.AbortWithStatusJSON(http.StatusFound, gin.H{"message": "Not logged in", "redirect": "/login"})
		return ""
	}

	userID, ok := userIDRaw.(string)
	if !ok {
		c.Header("Location", "/login")
		c.AbortWithStatusJSON(http.StatusFound, gin.H{"message": "Not logged in", "redirect": "/login"})
		return ""
	}
	return userID
}
