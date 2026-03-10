package middleware

import (
    "log"
    "github.com/gin-gonic/gin"
)

// JSONError logs the error and sends a JSON error response with the given HTTP status.
func JSONError(c *gin.Context, status int, msg string) {
    log.Print(msg)
    c.JSON(status, gin.H{"error": msg})
}
