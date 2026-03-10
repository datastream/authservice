package middleware

import (
    "net/http"
    "github.com/gin-gonic/gin"
)

// ServeStaticHTML serves a static HTML file from the ./static directory.
// It opens the file, obtains its modification time, and streams the content
// to the client. Any error encountered is returned so callers can handle it.
func ServeStaticHTML(c *gin.Context, filename string) error {
    // Open the file from the static directory.
    f, err := http.Dir("static").Open(filename)
    if err != nil {
        return err
    }
    defer f.Close()

    // Get file information for modification time.
    stat, err := f.Stat()
    if err != nil {
        return err
    }

    // Serve the file content.
    http.ServeContent(c.Writer, c.Request, filename, stat.ModTime(), f)
    return nil
}
