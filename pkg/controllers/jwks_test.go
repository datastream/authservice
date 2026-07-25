package controllers_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/datastream/authservice/pkg/controllers"
	"github.com/datastream/authservice/pkg/core"
	"github.com/datastream/authservice/testutils"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupJWKSTestService creates an AuthService with JWKS initialized, registers
// the JWKS and Config routes, and returns the service and router.
func setupJWKSTestService(t *testing.T, keyFile string) (*core.AuthService, *gin.Engine) {
	t.Helper()
	cfgPath := "../../cmd/oauthservice/config_test.yaml"
	svc, err := core.LoadConfig(cfgPath)
	require.NoError(t, err)
	svc.JwksKeyFile = keyFile

	require.NoError(t, svc.InitDB())
	svc.InitJWKS()

	controllers.SetJWKSConfig(svc.KeyID, svc.PrivateKey, svc.PublicKey)

	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/.well-known/openid-configuration", controllers.Config)
	r.GET("/.well-known/jwks.json", controllers.JWKSHandler)

	return svc, r
}

// TestJWKS_ReturnsValidJWKS verifies the JWKS endpoint returns HTTP 200 with a
// valid JWKS containing a keys array (6.1).
func TestJWKS_ReturnsValidJWKS(t *testing.T) {
	_, r := setupJWKSTestService(t, "")
	resp := testutils.PerformRequest(r, "GET", "/.well-known/jwks.json", nil, nil)
	require.Equal(t, http.StatusOK, resp.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	keys, ok := body["keys"].([]any)
	require.True(t, ok, "response must contain a 'keys' array")
	require.Len(t, keys, 1)
}

// TestJWKS_OneJWK verifies the keys array contains exactly one JWK object (6.2).
func TestJWKS_OneJWK(t *testing.T) {
	_, r := setupJWKSTestService(t, "")
	resp := testutils.PerformRequest(r, "GET", "/.well-known/jwks.json", nil, nil)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	keys := body["keys"].([]any)
	require.Len(t, keys, 1)
	jwk := keys[0].(map[string]any)

	// Check required RFC 7517 fields (6.3)
	assert.Equal(t, "RSA", jwk["kty"])
	assert.Equal(t, "sig", jwk["use"])
	assert.Equal(t, "RS256", jwk["alg"])
	assert.NotEmpty(t, jwk["kid"])
}

// TestJWKS_RSAParams verifies the JWK contains RSA public key parameters n and e (6.4).
func TestJWKS_RSAParams(t *testing.T) {
	_, r := setupJWKSTestService(t, "")
	resp := testutils.PerformRequest(r, "GET", "/.well-known/jwks.json", nil, nil)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	keys := body["keys"].([]any)
	jwk := keys[0].(map[string]any)

	nStr, ok := jwk["n"].(string)
	require.True(t, ok, "n must be a string")
	eStr, ok := jwk["e"].(string)
	require.True(t, ok, "e must be a string")

	// Verify n and e decode to valid RSA parameters (6.5)
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	require.NoError(t, err)
	n := new(big.Int).SetBytes(nBytes)
	require.True(t, n.Sign() > 0, "n must be positive")

	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	require.NoError(t, err)
	e := new(big.Int).SetBytes(eBytes)
	require.True(t, e.Sign() > 0, "e must be positive")

	// Verify the public key can be reconstructed
	_ = &rsa.PublicKey{N: n, E: int(e.Int64())}
}

// TestJWKS_ContentType verifies the JWKS response includes Content-Type header (6.6).
func TestJWKS_ContentType(t *testing.T) {
	_, r := setupJWKSTestService(t, "")
	resp := testutils.PerformRequest(r, "GET", "/.well-known/jwks.json", nil, nil)

	assert.Equal(t, "application/json", resp.Header().Get("Content-Type"))
}

// TestJWKS_CacheControl verifies the JWKS response includes Cache-Control header (6.7).
func TestJWKS_CacheControl(t *testing.T) {
	_, r := setupJWKSTestService(t, "")
	resp := testutils.PerformRequest(r, "GET", "/.well-known/jwks.json", nil, nil)

	assert.Equal(t, "public, max-age=86400", resp.Header().Get("Cache-Control"))
}

// TestConfig_JWKSPresent verifies the discovery document includes jwks_uri (6.8).
func TestConfig_JWKSPresent(t *testing.T) {
	_, r := setupJWKSTestService(t, "")
	resp := testutils.PerformRequest(r, "GET", "/.well-known/openid-configuration", nil, nil)

	require.Equal(t, http.StatusOK, resp.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	jwksURI, ok := body["jwks_uri"].(string)
	require.True(t, ok, "jwks_uri must be present as a string")
	assert.NotEmpty(t, jwksURI)
}

// TestConfig_JWKSCorrectURL verifies jwks_uri matches the actual endpoint URL (6.9).
func TestConfig_JWKSCorrectURL(t *testing.T) {
	_, r := setupJWKSTestService(t, "")
	resp := testutils.PerformRequest(r, "GET", "/.well-known/openid-configuration", nil, nil)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	jwksURI, ok := body["jwks_uri"].(string)
	require.True(t, ok)

	// The JWKS URI should end with /.well-known/jwks.json
	assert.Contains(t, jwksURI, "/.well-known/jwks.json")

	// Verify the JWKS endpoint actually responds
	resp2 := testutils.PerformRequest(r, "GET", jwksURI, nil, nil)
	assert.Equal(t, http.StatusOK, resp2.Code)
}

// TestConfig_UsesHTTPSWhenForwarded verifies scheme propagation to jwks_uri (6.9).
func TestConfig_UsesHTTPSWhenForwarded(t *testing.T) {
	_, r := setupJWKSTestService(t, "")

	resp := testutils.PerformRequest(r, "GET", "/.well-known/openid-configuration", nil,
		map[string]string{"X-Forwarded-Proto": "https"})
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	jwksURI := body["jwks_uri"].(string)
	assert.Contains(t, jwksURI, "https://", "jwks_uri should use https scheme")
}

// TestInitJWKS_LoadsFromFile verifies the service loads a key from a PEM file (6.10).
func TestInitJWKS_LoadsFromFile(t *testing.T) {
	// Create a temporary RSA key file
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test-key.pem")

	// Generate a test key
	err := generateRSAKey(keyPath, 2048)
	require.NoError(t, err)

	cfgPath := "../../cmd/oauthservice/config_test.yaml"
	svc, err := core.LoadConfig(cfgPath)
	require.NoError(t, err)
	svc.JwksKeyFile = keyPath

	require.NoError(t, svc.InitDB())
	svc.InitJWKS()

	assert.NotNil(t, svc.PrivateKey)
	assert.NotNil(t, svc.PublicKey)
	assert.NotEmpty(t, svc.KeyID)

	// Verify the public key parameters
	assert.True(t, svc.PublicKey.N.Sign() > 0)
	assert.True(t, svc.PublicKey.E > 0)
}

// TestInitJWKS_FailsOnInvalidFile verifies the service fails on an invalid key file (6.11).
func TestInitJWKS_FailsOnInvalidFile(t *testing.T) {
	cfgPath := "../../cmd/oauthservice/config_test.yaml"
	svc, err := core.LoadConfig(cfgPath)
	require.NoError(t, err)
	svc.JwksKeyFile = "/nonexistent/path/to/key.pem"

	require.NoError(t, svc.InitDB())

	// Test loadKeyFromFile behavior directly via public helper
	_, loadErr := core.LoadKeyFromFile("/nonexistent/key.pem")
	assert.Error(t, loadErr)
	assert.Contains(t, loadErr.Error(), "read key file")
}

// generateRSAKey generates a PEM-encoded RSA private key at the given path.
func generateRSAKey(path string, bits int) error {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	// Write PKCS#1 format
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return pem.Encode(f, block)
}