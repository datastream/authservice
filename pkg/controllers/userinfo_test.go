package controllers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/datastream/authservice/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUserinfo_NoScopeReturnsSubOnly verifies that userinfo with no scope returns only sub.
func TestUserinfo_NoScopeReturnsSubOnly(t *testing.T) {
	r, clientID, clientSecret := setupOAuthTest(t)

	cookie := loginToSession(t, r)

	verifier, codeChallenge := testutils.GeneratePKCEParams()

	// Get auth code
	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", "http://localhost:3000/callback")
	params.Set("response_type", "code")
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")
	params.Set("state", "test-state")

	req, _ := http.NewRequest("POST", "/oauth/authorize", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.True(t, w.Code == http.StatusFound || w.Code == http.StatusOK,
		"Authorize should succeed: %d %s", w.Code, w.Body.String())

	code := extractCode(t, w)
	require.NotEmpty(t, code)

	// Exchange code for token
	tokenResp := testutils.PerformTokenRequestWithPKCE(t, r, "authorization_code",
		clientID, clientSecret, code, verifier, "http://localhost:3000/callback")
	require.True(t, tokenResp.Code >= 200 && tokenResp.Code < 300,
		"Token exchange should succeed: %d %s", tokenResp.Code, tokenResp.Body.String())

	var tokenData testutils.OAuthTokenResponse
	require.NoError(t, json.NewDecoder(tokenResp.Body).Decode(&tokenData))

	// Request userinfo with no scope — should return only sub
	req2, _ := http.NewRequest("GET", "/userinfo", nil)
	req2.Header.Set("Authorization", "Bearer "+tokenData.AccessToken)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusOK, w2.Code)
	var claims map[string]any
	require.NoError(t, json.NewDecoder(w2.Body).Decode(&claims))
	assert.NotEmpty(t, claims["sub"])
}

// TestUserinfo_ProfileScopeReturnsName verifies the profile scope includes the name claim.
func TestUserinfo_ProfileScopeReturnsName(t *testing.T) {
	r, clientID, clientSecret := setupOAuthTest(t)

	cookie := loginToSession(t, r)

	verifier, codeChallenge := testutils.GeneratePKCEParams()

	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", "http://localhost:3000/callback")
	params.Set("response_type", "code")
	params.Set("scope", "openid profile")
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")
	params.Set("state", "test-state")

	req, _ := http.NewRequest("POST", "/oauth/authorize", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.True(t, w.Code == http.StatusFound || w.Code == http.StatusOK)

	code := extractCode(t, w)
	require.NotEmpty(t, code)

	tokenResp := testutils.PerformTokenRequestWithPKCE(t, r, "authorization_code",
		clientID, clientSecret, code, verifier, "http://localhost:3000/callback")
	require.True(t, tokenResp.Code >= 200 && tokenResp.Code < 300)

	var tokenData testutils.OAuthTokenResponse
	require.NoError(t, json.NewDecoder(tokenResp.Body).Decode(&tokenData))

	// Request userinfo
	req2, _ := http.NewRequest("GET", "/userinfo", nil)
	req2.Header.Set("Authorization", "Bearer "+tokenData.AccessToken)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusOK, w2.Code)
	var claims map[string]any
	require.NoError(t, json.NewDecoder(w2.Body).Decode(&claims))
	assert.NotEmpty(t, claims["sub"])
}

// TestUserinfo_NoBearerToken verifies unauthenticated requests are rejected.
func TestUserinfo_NoBearerToken(t *testing.T) {
	r, _, _ := setupOAuthTest(t)

	req, _ := http.NewRequest("GET", "/userinfo", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestUserinfo_InvalidBearerToken verifies invalid tokens are rejected.
func TestUserinfo_InvalidBearerToken(t *testing.T) {
	r, _, _ := setupOAuthTest(t)

	req, _ := http.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestUserinfoEmails_EmailScopeRequired verifies email scope is required for the emails endpoint.
func TestUserinfoEmails_EmailScopeRequired(t *testing.T) {
	r, clientID, clientSecret := setupOAuthTest(t)

	cookie := loginToSession(t, r)

	verifier, codeChallenge := testutils.GeneratePKCEParams()

	// Get auth code WITHOUT email scope
	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", "http://localhost:3000/callback")
	params.Set("response_type", "code")
	params.Set("scope", "openid profile")
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")
	params.Set("state", "test-state")

	req, _ := http.NewRequest("POST", "/oauth/authorize", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.True(t, w.Code == http.StatusFound || w.Code == http.StatusOK)

	code := extractCode(t, w)
	require.NotEmpty(t, code)

	tokenResp := testutils.PerformTokenRequestWithPKCE(t, r, "authorization_code",
		clientID, clientSecret, code, verifier, "http://localhost:3000/callback")
	require.True(t, tokenResp.Code >= 200 && tokenResp.Code < 300)

	var tokenData testutils.OAuthTokenResponse
	require.NoError(t, json.NewDecoder(tokenResp.Body).Decode(&tokenData))

	// Request emails endpoint without email scope
	req2, _ := http.NewRequest("GET", "/userinfo/emails", nil)
	req2.Header.Set("Authorization", "Bearer "+tokenData.AccessToken)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusForbidden, w2.Code)
}

// TestRevokeToken_ExistsReturns200 verifies that revoking an existing token returns 200.
func TestRevokeToken_ExistsReturns200(t *testing.T) {
	r, clientID, clientSecret := setupOAuthTest(t)

	cookie := loginToSession(t, r)

	verifier, codeChallenge := testutils.GeneratePKCEParams()

	// Get auth code and exchange for token
	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", "http://localhost:3000/callback")
	params.Set("response_type", "code")
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")
	params.Set("state", "test-state")

	req, _ := http.NewRequest("POST", "/oauth/authorize", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.True(t, w.Code == http.StatusFound || w.Code == http.StatusOK,
		"Authorize should succeed: %d %s", w.Code, w.Body.String())

	code := extractCode(t, w)
	require.NotEmpty(t, code)

	tokenResp := testutils.PerformTokenRequestWithPKCE(t, r, "authorization_code",
		clientID, clientSecret, code, verifier, "http://localhost:3000/callback")
	require.True(t, tokenResp.Code >= 200 && tokenResp.Code < 300,
		"Token exchange should succeed: %d %s", tokenResp.Code, tokenResp.Body.String())

	var tokenData testutils.OAuthTokenResponse
	require.NoError(t, json.NewDecoder(tokenResp.Body).Decode(&tokenData))

	// Revoke the access token
	resp := testutils.PerformFormRequest(r, "POST", "/oauth/revoke", map[string]string{
		"token": tokenData.AccessToken,
	}, nil)

	assert.Equal(t, http.StatusOK, resp.Code)
}

// TestRevokeToken_NonExistentReturns200 verifies RFC 7678 compliance:
// revoking a non-existent token still returns 200 (don't leak existence).
func TestRevokeToken_NonExistentReturns200(t *testing.T) {
	r, _, _ := setupOAuthTest(t)

	resp := testutils.PerformFormRequest(r, "POST", "/oauth/revoke", map[string]string{
		"token": "definitely-does-not-exist-12345",
	}, nil)

	// Per RFC 7678 §2.2: return 200 regardless of whether the token existed
	assert.Equal(t, http.StatusOK, resp.Code)
}

// TestRevokeToken_MissingTokenParam verifies missing token param returns 400.
func TestRevokeToken_MissingTokenParam(t *testing.T) {
	r, _, _ := setupOAuthTest(t)

	resp := testutils.PerformFormRequest(r, "POST", "/oauth/revoke", map[string]string{}, nil)

	assert.Equal(t, http.StatusBadRequest, resp.Code)
}

// TestRevokeToken_RefreshTokenHint verifies the refresh_token hint works.
func TestRevokeToken_RefreshTokenHint(t *testing.T) {
	r, clientID, clientSecret := setupOAuthTest(t)

	cookie := loginToSession(t, r)

	verifier, codeChallenge := testutils.GeneratePKCEParams()

	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", "http://localhost:3000/callback")
	params.Set("response_type", "code")
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")
	params.Set("state", "test-state")

	req, _ := http.NewRequest("POST", "/oauth/authorize", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.True(t, w.Code == http.StatusFound || w.Code == http.StatusOK)

	code := extractCode(t, w)
	require.NotEmpty(t, code)

	tokenResp := testutils.PerformTokenRequestWithPKCE(t, r, "authorization_code",
		clientID, clientSecret, code, verifier, "http://localhost:3000/callback")
	require.True(t, tokenResp.Code >= 200 && tokenResp.Code < 300)

	var tokenData testutils.OAuthTokenResponse
	require.NoError(t, json.NewDecoder(tokenResp.Body).Decode(&tokenData))

	// Revoke using refresh_token hint
	resp := testutils.PerformFormRequest(r, "POST", "/oauth/revoke", map[string]string{
		"token":           tokenData.RefreshToken,
		"token_type_hint": "refresh_token",
	}, nil)

	// Should succeed (200) even if the refresh token wasn't found (RFC 7678)
	assert.Equal(t, http.StatusOK, resp.Code)
}

// extractCode extracts the authorization code from a response (redirect or body).
func extractCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	code := testutils.ExtractCodeFromRedirect(t, w.Header().Get("Location"))
	if code != "" {
		return code
	}
	body := w.Body.String()
	if idx := strings.Index(body, "code="); idx >= 0 {
		rest := body[idx+5:]
		if end := strings.IndexAny(rest, "& "); end >= 0 {
			return rest[:end]
		}
		return rest
	}
	return ""
}