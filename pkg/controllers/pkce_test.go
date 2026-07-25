package controllers_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/datastream/authservice/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	setupOnce sync.Once
	setupR    http.Handler
	setupCID  string
	setupCS   string
)

func setupOAuthTest(t *testing.T) (http.Handler, string, string) {
	t.Helper()

	setupOnce.Do(func() {
		// Remove DB before first test to ensure clean state
		_ = os.Remove("/tmp/test_authserver.db")

		svc, r := testutils.LoadTestService(t)
		testutils.CreateTestUser(t, svc.DB, "alice", "password123")

		setupR = r
		setupCID, setupCS = testutils.CreateTestClient(t, "alice",
			"testapp.example.com", "http://localhost:3000/callback")
	})
	return setupR, setupCID, setupCS
}

// TestAuthorizeNoCodeChallengeRejected verifies that requests without code_challenge
// are rejected when ForcePKCE=true.
func TestAuthorizeNoCodeChallengeRejected(t *testing.T) {
	r, clientID, _ := setupOAuthTest(t)

	cookie := loginToSession(t, r)

	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", "http://localhost:3000/callback")
	params.Set("response_type", "code")
	params.Set("state", "test-state")

	req, _ := http.NewRequest("POST", "/oauth/authorize", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.True(t, w.Code == 400 || w.Code == 401,
		"Missing PKCE should be rejected, got %d: %s", w.Code, w.Body.String())
}

// TestAuthorizeApproveMissingCodeChallenge verifies POST approve without
// code_challenge returns 400.
func TestAuthorizeApproveMissingCodeChallenge(t *testing.T) {
	r, clientID, _ := setupOAuthTest(t)

	cookie := loginToSession(t, r)

	form := map[string]string{
		"client_id":             clientID,
		"redirect_uri":          "http://localhost:3000/callback",
		"state":                 "test-state",
		"code_challenge":        "",
		"code_challenge_method": "",
	}
	resp := testutils.PerformFormRequest(r, "POST", "/oauth/authorize/approve", form,
		map[string]string{"Cookie": cookie})

	assert.True(t, resp.Code == http.StatusBadRequest,
		"Missing code_challenge should return 400, got %d: %s", resp.Code, resp.Body.String())
}

// TestAuthorizeApproveInvalidCodeChallengeMethod verifies that invalid methods are rejected.
func TestAuthorizeApproveInvalidCodeChallengeMethod(t *testing.T) {
	r, clientID, _ := setupOAuthTest(t)

	cookie := loginToSession(t, r)

	form := map[string]string{
		"client_id":             clientID,
		"redirect_uri":          "http://localhost:3000/callback",
		"state":                 "test-state",
		"code_challenge":        "some-challenge",
		"code_challenge_method": "invalid_method",
	}
	resp := testutils.PerformFormRequest(r, "POST", "/oauth/authorize/approve", form,
		map[string]string{"Cookie": cookie})

	assert.True(t, resp.Code == http.StatusBadRequest,
		"Invalid challenge method should return 400, got %d: %s", resp.Code, resp.Body.String())
}

// TestAuthorizeApproveValidS256 verifies that S256 code challenge method works.
func TestAuthorizeApproveValidS256(t *testing.T) {
	r, clientID, _ := setupOAuthTest(t)

	cookie := loginToSession(t, r)

	_, codeChallenge := testutils.GeneratePKCEParams()

	form := map[string]string{
		"client_id":             clientID,
		"redirect_uri":          "http://localhost:3000/callback",
		"state":                 "test-state",
		"code_challenge":        codeChallenge,
		"code_challenge_method": "S256",
	}
	resp := testutils.PerformFormRequest(r, "POST", "/oauth/authorize/approve", form,
		map[string]string{"Cookie": cookie})

	assert.True(t, resp.Code == http.StatusFound || resp.Code == http.StatusOK,
		"Valid S256 should succeed, got %d: %s", resp.Code, resp.Body.String())
}

// TestAuthorizeApproveValidPlain verifies that plain code challenge method works.
func TestAuthorizeApproveValidPlain(t *testing.T) {
	r, clientID, _ := setupOAuthTest(t)

	cookie := loginToSession(t, r)

	_, codeChallenge := testutils.GeneratePKCEParams()

	form := map[string]string{
		"client_id":             clientID,
		"redirect_uri":          "http://localhost:3000/callback",
		"state":                 "test-state",
		"code_challenge":        codeChallenge,
		"code_challenge_method": "plain",
	}
	resp := testutils.PerformFormRequest(r, "POST", "/oauth/authorize/approve", form,
		map[string]string{"Cookie": cookie})

	assert.True(t, resp.Code == http.StatusFound || resp.Code == http.StatusOK,
		"Valid plain should succeed, got %d: %s", resp.Code, resp.Body.String())
}

// TestTokenCodeChallengeVerification_S256 verifies token exchange with correct S256 verifier.
func TestTokenCodeChallengeVerification_S256(t *testing.T) {
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
	require.True(t, w.Code == http.StatusFound || w.Code == http.StatusOK,
		"Authorize should succeed with PKCE: %d %s", w.Code, w.Body.String())

	code := testutils.ExtractCodeFromRedirect(t, w.Header().Get("Location"))
	if code == "" {
		idx := strings.Index(w.Body.String(), "code=")
		if idx >= 0 {
			rest := w.Body.String()[idx+5:]
			if end := strings.IndexAny(rest, "& "); end >= 0 {
				code = rest[:end]
			} else {
				code = rest
			}
		}
	}
	require.NotEmpty(t, code)

	tokenResp := testutils.PerformTokenRequestWithPKCE(t, r, "authorization_code",
		clientID, clientSecret, code, verifier, "http://localhost:3000/callback")

	assert.True(t, tokenResp.Code >= 200 && tokenResp.Code < 300,
		"Token exchange with correct verifier should succeed: %d %s", tokenResp.Code, tokenResp.Body.String())
}

// TestTokenCodeChallengeVerification_WrongVerifier verifies that a wrong code_verifier
// is rejected during token exchange.
func TestTokenCodeChallengeVerification_WrongVerifier(t *testing.T) {
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

	code := testutils.ExtractCodeFromRedirect(t, w.Header().Get("Location"))
	require.NotEmpty(t, code)

	wrongVerifier := verifier + "wrong"
	tokenResp := testutils.PerformTokenRequestWithPKCE(t, r, "authorization_code",
		clientID, clientSecret, code, wrongVerifier, "http://localhost:3000/callback")

	assert.True(t, tokenResp.Code < 200 || tokenResp.Code >= 300,
		"Wrong verifier should be rejected, got %d: %s", tokenResp.Code, tokenResp.Body.String())
}