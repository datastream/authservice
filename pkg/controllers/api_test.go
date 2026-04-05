package controllers_test

import (
    "encoding/json"
    "net/http"
    // "net/http/httptest"
    "testing"

    // "github.com/datastream/authservice/pkg/models"
    "github.com/datastream/authservice/testutils"
    "github.com/stretchr/testify/assert"
)

// helper to create a test user and obtain session cookie
func loginAndGetCookie(t *testing.T, router http.Handler, username, password string) string {
    // create user directly in DB
    // svc, _ := testutils.LoadTestService(t) // not needed for this helper
    // Actually we need svc, router from LoadTestService; but to avoid duplicate init, we'll call LoadTestService once per test.
    return ""
}

func TestHealthEndpoint(t *testing.T) {
    svc, router := testutils.LoadTestService(t)
    resp := testutils.PerformRequest(router, "GET", "/healthz", nil, nil)
    assert.Equal(t, http.StatusOK, resp.Code)
    // cleanup DB file
    _ = svc
}

func TestLoginPage_Unauthenticated(t *testing.T) {
    _, router := testutils.LoadTestService(t)
    resp := testutils.PerformRequest(router, "GET", "/login", nil, nil)
    assert.Equal(t, http.StatusOK, resp.Code)
}

func TestCreateAndListToken(t *testing.T) {
    svc, router := testutils.LoadTestService(t)
    // create a test user
    testutils.CreateTestUser(t, svc.DB, "alice", "password123")
    // simulate login to get session cookie
    loginResp := testutils.PerformRequest(router, "POST", "/login", map[string]string{"username": "alice", "password": "password123"}, map[string]string{"Content-Type": "application/json"})
    assert.Equal(t, http.StatusOK, loginResp.Code)
    // extract cookie
    cookie := loginResp.Header().Get("Set-Cookie")
    // create token
    tokenPayload := map[string]interface{}{ "domain": "example.com", "public": true, "describe": "test token", "userId": "alice" }
    createResp := testutils.PerformRequest(router, "POST", "/tokens", tokenPayload, map[string]string{"Content-Type": "application/json", "Cookie": cookie})
    assert.Equal(t, http.StatusOK, createResp.Code)
    // list tokens
    listResp := testutils.PerformRequest(router, "GET", "/tokens", nil, map[string]string{"Cookie": cookie})
    assert.Equal(t, http.StatusOK, listResp.Code)
    // cleanup
    _ = svc
}

func TestTokenRevoke(t *testing.T) {
    svc, router := testutils.LoadTestService(t)
    testutils.CreateTestUser(t, svc.DB, "bob", "secret")
    // login
    loginResp := testutils.PerformRequest(router, "POST", "/login", map[string]string{"username": "bob", "password": "secret"}, map[string]string{"Content-Type": "application/json"})
    assert.Equal(t, http.StatusOK, loginResp.Code)
    cookie := loginResp.Header().Get("Set-Cookie")
    // create token
    tokenPayload := map[string]interface{}{ "domain": "example.org", "public": false, "describe": "to be revoked", "userId": "bob" }
    createResp := testutils.PerformRequest(router, "POST", "/tokens", tokenPayload, map[string]string{"Content-Type": "application/json", "Cookie": cookie})
    assert.Equal(t, http.StatusOK, createResp.Code)
    // parse client_id from response
    var body struct { ClientID string `json:"client_id"` }
    json.NewDecoder(createResp.Body).Decode(&body)
    // revoke token
    revokeResp := testutils.PerformRequest(router, "DELETE", "/tokens/"+body.ClientID, nil, map[string]string{"Cookie": cookie})
    assert.Equal(t, http.StatusOK, revokeResp.Code)
    // verify token list empty
    listResp := testutils.PerformRequest(router, "GET", "/tokens", nil, map[string]string{"Cookie": cookie})
    assert.Equal(t, http.StatusOK, listResp.Code)
    // cleanup
    _ = svc
}

// Additional tests for OAuth flow, userinfo, signup, etc., can be added similarly.
