package middleware

import (
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
