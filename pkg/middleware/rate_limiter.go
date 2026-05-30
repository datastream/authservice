package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type loginRateLimiter struct {
	entries     map[string]*loginEntry
	mu          sync.Mutex
	maxAttempts int
}

type loginEntry struct {
	attempts     int
	windowStart  time.Time
	lockoutUntil time.Time
}

var loginLimiter = &loginRateLimiter{
	entries:     make(map[string]*loginEntry),
	maxAttempts: 10,
}

// LoginRateLimit enforces a per-username brute force limit:
// 10 failed login attempts within a 5-minute window triggers a 15-minute lockout.
// Only counts failed authentication attempts — successful logins do not consume the budget.
func LoginRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		username := extractLoginUsername(c)
		if username == "" {
			c.Next()
			return
		}

		// Acquire the entry under lock
		loginLimiter.mu.Lock()
		entry, exists := loginLimiter.entries[username]
		if !exists {
			entry = &loginEntry{
				windowStart: time.Now(),
			}
			loginLimiter.entries[username] = entry
		}

		// Reset window every 5 minutes
		if time.Since(entry.windowStart) > 5*time.Minute {
			entry.attempts = 0
			entry.windowStart = time.Now()
		}

		// Check if still in lockout period
		if time.Now().Before(entry.lockoutUntil) {
			loginLimiter.mu.Unlock()
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "Too many login attempts. Please try again later.",
			})
			return
		}

		// Unlock before calling handler. We use a context key to receive
		// a failure signal from the handler. On failure the handler records
		// to the entry; on success we do nothing.
		c.Set("loginRateLimitEntry", entry)
		loginLimiter.mu.Unlock()

		c.Next()
	}
}

// RecordLoginFailure must be called by login handlers when authentication fails.
// It increments the brute force counter for the given username.
func RecordLoginFailure(username string) {
	loginLimiter.mu.Lock()
	defer loginLimiter.mu.Unlock()

	entry, exists := loginLimiter.entries[username]
	if !exists {
		return
	}

	entry.attempts++
	if entry.attempts >= loginLimiter.maxAttempts {
		entry.lockoutUntil = time.Now().Add(15 * time.Minute)
		entry.attempts = 0
	}
}

// CheckLoginLockout returns true if the given username is currently locked out.
// This is useful for handlers that need to check lockout before attempting auth.
func CheckLoginLockout(username string) bool {
	loginLimiter.mu.Lock()
	defer loginLimiter.mu.Unlock()

	entry, exists := loginLimiter.entries[username]
	if !exists {
		return false
	}
	if time.Since(entry.windowStart) > 5*time.Minute {
		return false
	}
	return time.Now().Before(entry.lockoutUntil)
}

// extractLoginUsername pulls the username from either a form-encoded body
// or a JSON body so that the rate limiter covers both /login (form) and
// /api/login (JSON) endpoints.
func extractLoginUsername(c *gin.Context) string {
	// Try form first (fast path for x-www-form-urlencoded)
	if u := c.PostForm("username"); u != "" {
		return u
	}
	// Fall back to JSON body
	if strings.Contains(c.GetHeader("Content-Type"), "json") {
		var raw map[string]json.RawMessage
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			return ""
		}
		// Restore body for downstream handlers
		c.Request.Body = io.NopCloser(bytes.NewReader(body))
		c.Request.ContentLength = int64(len(body))
		if err := json.Unmarshal(body, &raw); err != nil {
			return ""
		}
		if u, ok := raw["username"]; ok {
			var s string
			if err := json.Unmarshal(u, &s); err == nil {
				return s
			}
		}
	}
	return ""
}
