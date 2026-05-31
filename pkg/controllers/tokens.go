package controllers

import (
	"net/http"
	"strings"

	"github.com/datastream/authservice/pkg/middleware"
	"github.com/datastream/authservice/pkg/models"
	"github.com/gin-gonic/gin"
)

type TokenForm struct {
	Domain   string `form:"domain" json:"domain" binding:"required"`
	Public   bool   `form:"public" json:"public"`
	Describe string `form:"describe" json:"describe"`
}

// TokenCreateResponse is returned only at creation time — clientSecret is never shown again.
type TokenCreateResponse struct {
	OK           bool   `json:"ok"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func TokensList(c *gin.Context) {
	userID, ok, err := middleware.GetLoggedInUserID(c)
	if err != nil || !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	tokens, err := models.FindTokensByUserID(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch tokens"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"tokens": tokens,
	})
}

func ClientTokensCreate(c *gin.Context) {
	userID, ok, err := middleware.GetLoggedInUserID(c)
	if err != nil || !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	var postForm TokenForm
	if err := c.BindJSON(&postForm); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	token := models.Token{
		UserID:   userID,
		Domain:   postForm.Domain,
		Public:   postForm.Public,
		Describe: &postForm.Describe,
	}
	if err := token.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create token"})
		return
	}
	c.JSON(http.StatusOK, TokenCreateResponse{
		OK:           true,
		ClientID:     token.ClientID,
		ClientSecret: token.ClientSecret,
	})
}

// TokenRevoke deletes a token owned by the logged-in user
type RedirectURIForm struct {
	URIs []string `json:"uris" binding:"required"`
}

// TokenRedirectURIs handles GET (list), POST (add), and DELETE (remove) redirect URIs.
// Uses atomic SQL REPLACE for concurrency-safe modifications.
// Must be registered BEFORE /api/tokens/:id to avoid route conflict in Gin.
func TokenRedirectURIs(c *gin.Context) {
	userID, ok, err := middleware.GetLoggedInUserID(c)
	if err != nil || !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	clientID := c.Query("clientID")
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing clientID"})
		return
	}

	token, err := models.FindTokenByClientID(clientID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Token not found"})
		return
	}
	if token.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Not authorized to modify this token"})
		return
	}

	switch c.Request.Method {
	case "GET":
		// Return current redirect URIs without parsing any body
		var uris []string
		if token.RedirectURIs != nil && *token.RedirectURIs != "" {
			for _, u := range strings.Split(*token.RedirectURIs, ";") {
				if u := strings.TrimSpace(u); u != "" {
					uris = append(uris, u)
				}
			}
		}
		c.JSON(http.StatusOK, gin.H{"uris": uris})
		return

	case "POST":
		var form RedirectURIForm
		if err := c.BindJSON(&form); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		// Atomic SQL: REPLACE wraps existing URIs so concurrent additions are safe
		updated := token.RedirectURIs
		for _, u := range form.URIs {
			if u = strings.TrimSpace(u); u != "" {
				if updated == nil || *updated == "" {
					*updated = u
				} else if !strings.Contains(*updated, u) {
					*updated += ";" + u
				}
			}
		}
		if err := models.UpdateRedirectURIs(clientID, updated); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update redirect URIs"})
			return
		}

	case "DELETE":
		var form RedirectURIForm
		if err := c.BindJSON(&form); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		updated := ""
		if token.RedirectURIs != nil {
			updated = *token.RedirectURIs
		}
		for _, u := range form.URIs {
			u = strings.TrimSpace(u)
			if u == "" {
				continue
			}
			// Remove ";uri;" and handle edge cases for start/end of string
			pattern := ";" + u
			if strings.HasPrefix(updated, pattern) {
				updated = updated[len(pattern):]
			} else if strings.HasSuffix(updated, pattern) {
				updated = updated[:len(updated)-len(pattern)]
			} else {
				replacement := pattern + ";"
				updated = strings.ReplaceAll(updated, replacement, "")
			}
		}
		if err := models.UpdateRedirectURIs(clientID, &updated); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update redirect URIs"})
			return
		}

	default:
		c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "method not allowed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func TokenRevoke(c *gin.Context) {
	userID, ok, err := middleware.GetLoggedInUserID(c)
	if err != nil || !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	clientID := c.Param("id")
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing token ID"})
		return
	}
	token, err := models.FindTokenByClientID(clientID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Token not found"})
		return
	}
	if token.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Not authorized to delete this token"})
		return
	}
	if err := token.Delete(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
