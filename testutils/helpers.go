package testutils

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/datastream/authservice/pkg/core"
	"github.com/datastream/authservice/pkg/controllers"
	"github.com/datastream/authservice/pkg/models"
	"github.com/stretchr/testify/require"
)

// LoadTestService loads the AuthService using the test config and initializes
// DB, OAuth server, and JWKS. The router mirrors main.go routes.
func LoadTestService(t *testing.T) (*core.AuthService, *gin.Engine) {
	t.Helper()
	cfgPath := "../../cmd/oauthservice/config_test.yaml"
	svc, err := core.LoadConfig(cfgPath)
	require.NoError(t, err)
	require.NoError(t, svc.InitDB())
	require.NoError(t, svc.InitOAuthServer())
	svc.InitJWKS()
	controllers.SetJWKSConfig(svc.KeyID, svc.PrivateKey, svc.PublicKey)

	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// SPA APIs
	r.POST("/api/login", controllers.LoginAPI)
	r.POST("/api/signup", controllers.SignupAPI)
	r.POST("/api/logout", controllers.LogoutAPI)
	r.GET("/api/me", controllers.MeAPI)

	// Token management
	r.GET("/api/tokens", controllers.TokensList)
	r.POST("/api/tokens", controllers.ClientTokensCreate)
	r.DELETE("/api/tokens/:id", controllers.TokenRevoke)

	// OAuth routes
	oauth := controllers.NewOAuthController(svc.Server)
	r.GET("/oauth/authorize", oauth.OAuthHandler)
	r.POST("/oauth/authorize", oauth.OAuthHandler)
	r.POST("/oauth/authorize/approve", oauth.AuthorizeApprove)
	r.POST("/login", oauth.Login)
	r.POST("/oauth/token", oauth.TokenHandler)
	r.GET("/userinfo", oauth.Userinfo)
	r.GET("/userinfo/emails", oauth.UserinfoEmails)
	r.POST("/oauth/revoke", oauth.RevokeToken)

	// OIDC discovery
	r.GET("/.well-known/openid-configuration", controllers.Config)
	r.GET("/.well-known/jwks.json", controllers.JWKSHandler)

	return svc, r
}

// PerformRequest is a helper to execute a request against the provided router.
func PerformRequest(r http.Handler, method, path string, body interface{}, headers map[string]string) *httptest.ResponseRecorder {
	var reqBody []byte
	if body != nil {
		reqBody, _ = json.Marshal(body)
	}
	req, _ := http.NewRequest(method, path, bytes.NewReader(reqBody))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// PerformFormRequest executes a form-encoded request against the provided router.
func PerformFormRequest(r http.Handler, method, path string, form map[string]string, headers map[string]string) *httptest.ResponseRecorder {
	formData := url.Values{}
	for k, v := range form {
		formData.Set(k, v)
	}
	req, _ := http.NewRequest(method, path, strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// PerformRequestWithBody executes a request with a raw io.Reader body.
func PerformRequestWithBody(r http.Handler, method, path string, body io.Reader, headers map[string]string) *httptest.ResponseRecorder {
	req, _ := http.NewRequest(method, path, body)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// CreateTestUser creates a user directly via the models for authentication tests.
func CreateTestUser(t *testing.T, conn *sql.DB, username, password string) {
	t.Helper()
	u := models.NewUser(username, "")
	require.NoError(t, u.GenHashedPassword(password))
	require.NoError(t, u.Save())
}

// StringPtr returns a pointer to the given string.
func StringPtr(s string) *string {
	return &s
}

// CreateTestClient creates an OAuth client (Token model) for the given user
// with the specified domain and redirect URIs. Returns the client_id and
// client_secret for use in tests.
func CreateTestClient(t *testing.T, userID, domain, redirectURIs string) (clientID, clientSecret string) {
	t.Helper()
	token := &models.Token{
		UserID:       userID,
		Domain:       domain,
		Public:       true,
		Description:  StringPtr("test client"),
		RedirectURIs: StringPtr(redirectURIs),
	}
	require.NoError(t, token.Save())
	return token.ClientID, token.ClientSecret
}

// GeneratePKCEParams generates a code verifier and S256 code challenge pair.
// Uses a deterministic repeating pattern for reproducibility.
func GeneratePKCEParams() (codeVerifier, codeChallenge string) {
	bytes := make([]byte, 32)
	for i := range bytes {
		bytes[i] = byte(97 + i%26) // 'a'-'z' repeating pattern
	}
	codeVerifier = string(bytes)
	codeChallenge = GenerateCodeChallenge(codeVerifier)
	return
}

// GenerateCodeChallenge generates a code_challenge from a code_verifier using SHA-256.
func GenerateCodeChallenge(codeVerifier string) string {
	h := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// ParseSessionCookie extracts the session cookie from a ResponseRecorder.
func ParseSessionCookie(resp *httptest.ResponseRecorder) string {
	c := resp.Header().Get("Set-Cookie")
	if idx := strings.IndexByte(c, ';'); idx > 0 {
		return c[:idx]
	}
	return c
}

// ExtractCodeFromRedirect extracts the authorization code from a redirect Location header.
func ExtractCodeFromRedirect(t *testing.T, location string) string {
	t.Helper()
	if location == "" {
		return ""
	}
	loc := location
	if idx := strings.Index(loc, "://"); idx >= 0 {
		loc = loc[idx+3:]
	}
	if idx := strings.Index(loc, "/oauth/authorize"); idx >= 0 {
		loc = loc[idx:]
	}
	if idx := strings.Index(loc, "?"); idx < 0 {
		return ""
	} else {
		query := loc[idx+1:]
		v, err := url.ParseQuery(query)
		if err != nil {
			return ""
		}
		return v.Get("code")
	}
}

// OAuthTokenResponse represents the response from a successful /oauth/token request.
type OAuthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// ParseOAuthTokenResponse parses the response from a successful /oauth/token request.
func ParseOAuthTokenResponse(t *testing.T, resp *httptest.ResponseRecorder) OAuthTokenResponse {
	t.Helper()
	var respData OAuthTokenResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&respData))
	require.NotEmpty(t, respData.AccessToken, "access_token should be present")
	return respData
}

// GenerateRandomString generates a cryptographically random hex string of the given length.
func GenerateRandomString(n int) string {
	b := make([]byte, n/2)
	_, err := rand.Read(b)
	if err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return strings.TrimRight(encodeHex(b), "=")
}

func encodeHex(b []byte) string {
	h := make([]byte, len(b)*2)
	for i, v := range b {
		h[i*2] = "0123456789abcdef"[v>>4]
		h[i*2+1] = "0123456789abcdef"[v&0xf]
	}
	return string(h)
}

// BuildAuthorizeParams creates the query parameters for an OAuth authorize request.
func BuildAuthorizeParams(t *testing.T, clientID, redirectURI, state string) url.Values {
	t.Helper()
	v := url.Values{}
	v.Set("client_id", clientID)
	v.Set("redirect_uri", redirectURI)
	v.Set("state", state)
	return v
}

// BuildAuthorizeParamsWithPKCE creates the query parameters with PKCE for an OAuth authorize request.
func BuildAuthorizeParamsWithPKCE(t *testing.T, clientID, redirectURI, state string, codeChallenge, codeChallengeMethod string) url.Values {
	t.Helper()
	params := BuildAuthorizeParams(t, clientID, redirectURI, state)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", codeChallengeMethod)
	return params
}

// PerformAuthorizeRequest performs an OAuth authorize request.
func PerformAuthorizeRequest(r http.Handler, params url.Values) *httptest.ResponseRecorder {
	return PerformRequest(r, "GET", "/oauth/authorize?"+params.Encode(), nil, nil)
}

// PerformAuthorizeApproveRequest performs a POST to /oauth/authorize/approve.
func PerformAuthorizeApproveRequest(t *testing.T, r http.Handler, clientID, redirectURI, state, codeChallenge, codeChallengeMethod string, headers map[string]string) *httptest.ResponseRecorder {
	form := map[string]string{
		"client_id":             clientID,
		"redirect_uri":          redirectURI,
		"state":                 state,
		"code_challenge":        codeChallenge,
		"code_challenge_method": codeChallengeMethod,
	}
	return PerformFormRequest(r, "POST", "/oauth/authorize/approve", form, headers)
}

// PerformTokenRequest performs a POST to /oauth/token with form-encoded data.
func PerformTokenRequest(t *testing.T, r http.Handler, grantType, clientID, clientSecret, code, redirectURI string) *httptest.ResponseRecorder {
	form := map[string]string{
		"grant_type":    grantType,
		"client_id":     clientID,
		"client_secret": clientSecret,
	}
	if code != "" {
		form["code"] = code
	}
	if redirectURI != "" {
		form["redirect_uri"] = redirectURI
	}
	return PerformFormRequest(r, "POST", "/oauth/token", form, nil)
}

// PerformTokenRequestWithPKCE performs a token request with PKCE code_verifier.
func PerformTokenRequestWithPKCE(t *testing.T, r http.Handler, grantType, clientID, clientSecret, code, codeVerifier, redirectURI string) *httptest.ResponseRecorder {
	form := map[string]string{
		"grant_type":       grantType,
		"client_id":        clientID,
		"client_secret":    clientSecret,
		"code":             code,
		"code_verifier":    codeVerifier,
	}
	if redirectURI != "" {
		form["redirect_uri"] = redirectURI
	}
	return PerformFormRequest(r, "POST", "/oauth/token", form, nil)
}

// MustParseLocation parses the Location header and extracts the path.
func MustParseLocation(t *testing.T, resp *httptest.ResponseRecorder) string {
	t.Helper()
	loc := resp.Header().Get("Location")
	require.NotEmpty(t, loc, "Location header should be present")
	// If it's an absolute URL, extract the path
	if strings.HasPrefix(loc, "http") {
		u, err := url.Parse(loc)
		require.NoError(t, err)
		return u.Path + "?" + u.RawQuery
	}
	return loc
}

// GetAuthorizeCodeFromPostResponse extracts the authorization code from a POST response body.
// The go-oauth2 library returns form-encoded data in the body for POST requests.
func GetAuthorizeCodeFromPostResponse(t *testing.T, resp *httptest.ResponseRecorder) string {
	t.Helper()
	body := resp.Body.String()
	idx := strings.Index(body, "code=")
	if idx >= 0 {
		rest := body[idx+5:]
		end := strings.IndexAny(rest, "& ")
		if end >= 0 {
			return rest[:end]
		}
		return rest
	}
	// Try from Location header if present
	loc := resp.Header().Get("Location")
	if idx = strings.Index(loc, "code="); idx >= 0 {
		rest := loc[idx+5:]
		end := strings.IndexAny(rest, "& ")
		if end >= 0 {
			return rest[:end]
		}
		return rest
	}
	t.Fatalf("Could not find authorization code in response: body=%q headers=%v", body, resp.Header())
	return ""
}

// GetAuthorizeCodeFromJSONResponse extracts the authorization code from a JSON response body.
// This is for the AuthorizeApprove API path which may return JSON.
func GetAuthorizeCodeFromJSONResponse(t *testing.T, resp *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		// Not JSON; try form-encoded
		if code := GetAuthorizeCodeFromPostResponse(t, resp); code != "" {
			return code
		}
	}
	if code, ok := body["code"].(string); ok {
		return code
	}
	t.Fatalf("Could not find authorization code in JSON response: %v", body)
	return ""
}

// ParseOAuthErrorResponseMap parses an OAuth error response into a map.
func ParseOAuthErrorResponseMap(resp *httptest.ResponseRecorder) map[string]string {
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil
	}
	result := make(map[string]string)
	for k, v := range body {
		result[k] = v.(string)
	}
	return result
}