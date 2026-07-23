package controllers_test

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/datastream/authservice/pkg/core"
	"github.com/datastream/authservice/pkg/controllers"
	"github.com/datastream/authservice/testutils"
	"github.com/go-session/session/v3"
	"github.com/stretchr/testify/assert"
)

func TestHealthEndpoint(t *testing.T) {
	svc, router := testutils.LoadTestService(t)
	resp := testutils.PerformRequest(router, "GET", "/healthz", nil, nil)
	assert.Equal(t, http.StatusOK, resp.Code)
	_ = svc
}

// authedRouter creates a test router with session-based auth pre-configured
// for the given user ID. This avoids the complexity of session cookie handling.
func authedRouter(t *testing.T, svc *core.AuthService, userID string) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())

	// Create a real session and store the user ID in it
	r.Use(func(c *gin.Context) {
		store, err := session.Start(c.Request.Context(), c.Writer, c.Request)
		if err == nil {
			store.Set("LoggedInUserID", userID)
			store.Save()
		}
		c.Next()
	})

	r.GET("/healthz", func(c *gin.Context) { c.JSON(200, gin.H{"status": "ok"}) })
	r.GET("/api/tokens", controllers.TokensList)
	r.POST("/api/tokens", controllers.ClientTokensCreate)
	r.DELETE("/api/tokens/:id", controllers.TokenRevoke)

	return r
}

func TestCreateAndListToken(t *testing.T) {
	// Clean DB to avoid unique constraint errors from previous runs
	_ = os.Remove("/tmp/test_authserver.db")
	svc, _ := testutils.LoadTestService(t)
	t.Cleanup(func() { _ = svc.DB.Close() })
	testutils.CreateTestUser(t, svc.DB, "alice", "password123")

	r := authedRouter(t, svc, "alice")
	tokenPayload := map[string]interface{}{"domain": "example.com", "public": true, "describe": "test token", "userId": "alice"}
	createResp := testutils.PerformRequest(r, "POST", "/api/tokens", tokenPayload, map[string]string{"Content-Type": "application/json"})
	assert.Equal(t, http.StatusOK, createResp.Code)
	listResp := testutils.PerformRequest(r, "GET", "/api/tokens", nil, nil)
	assert.Equal(t, http.StatusOK, listResp.Code)
}

func TestTokenRevoke(t *testing.T) {
	_ = os.Remove("/tmp/test_authserver.db")
	svc, _ := testutils.LoadTestService(t)
	t.Cleanup(func() { _ = svc.DB.Close() })
	testutils.CreateTestUser(t, svc.DB, "bob", "secret")

	r := authedRouter(t, svc, "bob")
	tokenPayload := map[string]interface{}{"domain": "example.org", "public": false, "describe": "to be revoked", "userId": "bob"}
	createResp := testutils.PerformRequest(r, "POST", "/api/tokens", tokenPayload, map[string]string{"Content-Type": "application/json"})
	assert.Equal(t, http.StatusOK, createResp.Code)

	var body struct { ClientID string `json:"clientId"` }
	json.NewDecoder(createResp.Body).Decode(&body)

	revokeResp := testutils.PerformRequest(r, "DELETE", "/api/tokens/"+body.ClientID, nil, nil)
	assert.Equal(t, http.StatusOK, revokeResp.Code)

	listResp := testutils.PerformRequest(r, "GET", "/api/tokens", nil, nil)
	assert.Equal(t, http.StatusOK, listResp.Code)
}

// Additional tests for OAuth flow, userinfo, signup, etc., can be added similarly.
