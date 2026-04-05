package middleware

import "github.com/gin-gonic/gin"

// Fail sends a JSON error response with the given HTTP status and aborts the request.
// It is a thin wrapper around JSONError to provide a convenient shorthand used
// throughout the codebase.
func Fail(c *gin.Context, status int, msg string) {
    JSONError(c, status, msg)
    c.Abort()
}
