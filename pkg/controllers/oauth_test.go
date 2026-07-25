package controllers_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/datastream/authservice/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loginToSession(t *testing.T, r http.Handler) string {
	t.Helper()
	resp := testutils.PerformFormRequest(r, "POST", "/login",
		map[string]string{"username": "alice", "password": "password123"}, nil)
	require.Equal(t, http.StatusOK, resp.Code, "Login should succeed: %s", resp.Body.String())
	return testutils.ParseSessionCookie(resp)
}

// TestOAuthAuthorize_UnauthenticatedRedirectsToLogin verifies unauthenticated
// GET to /oauth/authorize redirects to /login.
func TestOAuthAuthorize_UnauthenticatedRedirectsToLogin(t *testing.T) {
	r, clientID, _ := setupOAuthTest(t)

	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", "http://localhost:3000/callback")
	params.Set("state", "test-state")
	params.Set("response_type", "code")
	_, challenge := testutils.GeneratePKCEParams()
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", "S256")

	resp := testutils.PerformRequest(r, "GET", "/oauth/authorize?"+params.Encode(), nil, nil)
	assert.Equal(t, http.StatusFound, resp.Code,
		"Unauthenticated GET should redirect to /login, got %d", resp.Code)
	assert.Contains(t, resp.Header().Get("Location"), "/login",
		"Redirect should go to /login")
}

// TestOAuthHandler_UnauthenticatedPOST verifies that an unauthenticated POST
// to /oauth/authorize produces an error (client validation fails before auth check).
func TestOAuthHandler_UnauthenticatedPOST(t *testing.T) {
	r, _, _ := setupOAuthTest(t)

	_, challenge := testutils.GeneratePKCEParams()
	resp := testutils.PerformFormRequest(r, "POST", "/oauth/authorize", map[string]string{
		"client_id":             "nonexistent-client",
		"redirect_uri":          "http://localhost:3000/callback",
		"response_type":         "code",
		"state":                 "test-state",
		"code_challenge":        challenge,
		"code_challenge_method": "S256",
	}, nil)

	// Per RFC 6749 §4.1.2.1, OAuth errors are returned as 302 redirects.
	assert.True(t, resp.Code == 302 || resp.Code == 400 || resp.Code == 401,
		"Non-existent client should produce error, got %d", resp.Code)
}

// TestOAuthHandler_POSTAuthorizeLogin verifies the /login endpoint works.
func TestOAuthHandler_POSTAuthorizeLogin(t *testing.T) {
	r, _, _ := setupOAuthTest(t)

	resp := testutils.PerformFormRequest(r, "POST", "/login",
		map[string]string{"username": "alice", "password": "password123"}, nil)

	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Contains(t, resp.Body.String(), "Login successful")
}

// TestAuthorizeApprove_MissingParams verifies the AuthorizeApprove endpoint
// rejects requests without required parameters.
func TestAuthorizeApprove_MissingParams(t *testing.T) {
	r, _, _ := setupOAuthTest(t)

	resp := testutils.PerformFormRequest(r, "POST", "/oauth/authorize/approve",
		map[string]string{}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.Code)
}

// TestAuthorizeApprove_Unauthenticated verifies that approve without session is rejected.
func TestAuthorizeApprove_Unauthenticated(t *testing.T) {
	r, _, _ := setupOAuthTest(t)

	_, codeChallenge := testutils.GeneratePKCEParams()

	resp := testutils.PerformAuthorizeApproveRequest(t, r,
		"test-client-id-001", "http://localhost:3000/callback", "state",
		codeChallenge, "S256", nil)

	assert.True(t, resp.Code == http.StatusForbidden || resp.Code == http.StatusInternalServerError || resp.Code == 401,
		"Unauthenticated approve should fail, got %d", resp.Code)
}

func TestOAuthAuthorize_RedirectURIValidation_Invalid(t *testing.T) {
	r, clientID, _ := setupOAuthTest(t)

	cookie := loginToSession(t, r)

	_, challenge := testutils.GeneratePKCEParams()
	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", "http://localhost:9999/callback")
	params.Set("response_type", "code")
	params.Set("state", "test-state")
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", "S256")

	req, _ := http.NewRequest("POST", "/oauth/authorize", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Per RFC 6749 §4.1.2.1, OAuth errors are returned as 302 redirects.
	assert.True(t, w.Code == 302 || w.Code == 400 || w.Code == 401,
		"Invalid redirect URI should produce error, got %d: %s", w.Code, w.Body.String())
}

// TestOAuthAuthorize_RedirectURIValidation_HostMismatch verifies host mismatches are rejected.
func TestOAuthAuthorize_RedirectURIValidation_HostMismatch(t *testing.T) {
	r, clientID, _ := setupOAuthTest(t)

	cookie := loginToSession(t, r)

	_, challenge := testutils.GeneratePKCEParams()
	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", "http://evil.example.com/callback")
	params.Set("response_type", "code")
	params.Set("state", "test-state")
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", "S256")

	req, _ := http.NewRequest("POST", "/oauth/authorize", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Per RFC 6749 §4.1.2.1, OAuth errors are returned as 302 redirects
	// with error parameters in the query string.
	assert.True(t, w.Code == 302,
		"Host mismatch should produce 302 redirect with error, got %d: %s", w.Code, w.Body.String())
	loc := w.Header().Get("Location")
	assert.Contains(t, loc, "error=",
		"Redirect should contain error param, got Location: %s", loc)
	assert.Contains(t, loc, "invalid",
		"Redirect should indicate invalid redirect URI, got Location: %s", loc)
}

// TestOAuthAuthorize_MissingClientID verifies requests without client_id are rejected.
func TestOAuthAuthorize_MissingClientID(t *testing.T) {
	r, _, _ := setupOAuthTest(t)

	_, challenge := testutils.GeneratePKCEParams()
	resp := testutils.PerformFormRequest(r, "POST", "/oauth/authorize", map[string]string{
		"redirect_uri":          "http://localhost:3000/callback",
		"response_type":         "code",
		"state":                 "test-state",
		"code_challenge":        challenge,
		"code_challenge_method": "S256",
	}, nil)

	assert.True(t, resp.Code == 400 || resp.Code == 401,
		"Missing client_id should produce error, got %d", resp.Code)
}

// TestOAuthAuthorizeGET_PKCERedirectsToLogin verifies unauthenticated GET
// with PKCE params redirects to /login.
func TestOAuthAuthorizeGET_PKCERedirectsToLogin(t *testing.T) {
	r, clientID, _ := setupOAuthTest(t)

	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", "http://localhost:3000/callback")
	params.Set("response_type", "code")
	params.Set("state", "test-state")
	_, challenge := testutils.GeneratePKCEParams()
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", "S256")

	resp := testutils.PerformRequest(r, "GET", "/oauth/authorize?"+params.Encode(), nil, nil)
	assert.Equal(t, http.StatusFound, resp.Code,
		"Unauthenticated GET with PKCE should redirect to /login, got %d", resp.Code)
	assert.Contains(t, resp.Header().Get("Location"), "/login",
		"Redirect should go to /login")
}

// TestOAuthAuthorizeGET_ValidAuthenticated verifies GET with valid PKCE
// for an authenticated user produces a code (library renders consent or authorizes).
func TestOAuthAuthorizeGET_ValidAuthenticated(t *testing.T) {
	r, clientID, _ := setupOAuthTest(t)

	cookie := loginToSession(t, r)
	_, challenge := testutils.GeneratePKCEParams()

	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", "http://localhost:3000/callback")
	params.Set("response_type", "code")
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", "S256")
	params.Set("state", "test-state")

	req, _ := http.NewRequest("GET", "/oauth/authorize?"+params.Encode(), nil)
	req.Header.Set("Cookie", cookie)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// The library returns 302 (redirect to consent or directly to callback with code)
	// or 200 with body containing code= for POST-like processing.
	// We accept 302 (redirect to consent page) or 200 (direct authorize).
	assert.True(t, w.Code == http.StatusFound || w.Code == http.StatusOK,
		"Authenticated GET should succeed, got %d: %s", w.Code, w.Body.String())
}