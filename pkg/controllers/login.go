// Package controllers provides HTTP handlers for the OAuth service using the Gin framework.
// It includes controllers for login, OAuth authorization, token management, and FGA integration.
package controllers

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/datastream/authservice/pkg/models"
	sign4 "github.com/datastream/aws"
	"github.com/gin-gonic/gin"
	"github.com/go-session/session/v3"
)

// JWKSConfig holds the data needed by JWKS and Config handlers.
type JWKSConfig struct {
	KeyID   string
	PrivKey *rsa.PrivateKey
	PubKey  *rsa.PublicKey
}

var (
	jwksCfg   JWKSConfig
	jwksMu    sync.RWMutex
	jwksBytes []byte
)

// jwksResponse is the JSON structure for a JWKS document per RFC 7517.
type jwksResponse struct {
	Keys []jwksKey `json:"keys"`
}

// jwksKey represents a single JWK per RFC 7517.
type jwksKey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	KID string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// SetJWKSConfig updates the JWKS configuration with the server's key pair
// and pre-computes the cached JWKS JSON bytes for fast request handling.
func SetJWKSConfig(keyID string, privKey *rsa.PrivateKey, pubKey *rsa.PublicKey) {
	jwksCfg.KeyID = keyID
	jwksCfg.PrivKey = privKey
	jwksCfg.PubKey = pubKey

	// Pre-compute the JWKS document so every request avoids struct allocation + JSON marshaling.
	jwksBytes, _ = json.Marshal(jwksResponse{
		Keys: []jwksKey{
			{
				Kty: "RSA",
				Use: "sig",
				KID: keyID,
				Alg: "RS256",
				N:   base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes()),
			},
		},
	})
}

// JWKSHandler serves the server's public keys in RFC 7517 JWKS format.
func JWKSHandler(c *gin.Context) {
	jwksMu.RLock()
	data := jwksBytes
	jwksMu.RUnlock()

	c.Header("Content-Type", "application/json")
	c.Header("Cache-Control", "public, max-age=86400")
	c.Data(http.StatusOK, "application/json", data)
}

// Config serves the OpenID Connect configuration endpoint.

// LoginForm represents the login form fields.
type LoginForm struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" binding:"required"`
}

// TokenAuthRequest represents the authentication request body.
type TokenAuthRequest struct {
	RequestType string `json:"requestType"`
	AccessKey   string `json:"accessKey"`
	Timestamp   string `json:"timestamp"`
	Region      string `json:"region"`
	Service     string `json:"service"`
	VerifyData  string `json:"verifyData"`
	Signature   string `json:"signature"`
	Domain      string `json:"domain"`
}

// OIDC discovery config cache.
var (
	oidcConfig   map[string]any
	oidcConfigMu sync.RWMutex
)

func init() {
	oidcConfig = map[string]any{
		"issuer":                                "", // set per-request
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query", "fragment"},
		"claims_supported":                      []string{"sub", "name", "email", "email_verified"},
		"subject_types_supported":               []string{"public"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "basic"},
	}
}

// Config serves the OpenID Connect configuration endpoint.
func Config(c *gin.Context) {
	schema := c.Request.Header.Get("X-Forwarded-Proto")
	if schema == "" {
		schema = c.Request.URL.Scheme
	}
	if schema == "" {
		schema = "http"
	}
	issuer := fmt.Sprintf("%s://%s", schema, c.Request.Host)

	oidcConfigMu.RLock()
	cfg := make(map[string]any, len(oidcConfig))
	for k, v := range oidcConfig {
		cfg[k] = v
	}
	oidcConfigMu.RUnlock()

	cfg["issuer"] = issuer
	cfg["authorization_endpoint"] = issuer + "/oauth/authorize"
	cfg["token_endpoint"] = issuer + "/oauth/token"
	cfg["userinfo_endpoint"] = issuer + "/userinfo"
	cfg["jwks_uri"] = issuer + "/.well-known/jwks.json"
	c.JSON(http.StatusOK, cfg)
}

// checkAWSHMAC validates an AWS4-HMAC-SHA256 signed request.
func checkAWSHMAC(r *http.Request) (*models.AccessToken, error) {
	s, authString, signedHeaders, err := sign4.GetSignature(r)
	if err != nil {
		return nil, fmt.Errorf("failed to get signature: %w", err)
	}

	var tk models.AccessToken
	if err := tk.FindByAccessKey(s.AccessKey); err != nil {
		return nil, fmt.Errorf("failed to find token by access key: %w", err)
	}

	s.SecretKey = tk.SecretKey

	if err := s.SignRequest(r, signedHeaders); err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	if authString != r.Header.Get("Authorization") {
		return nil, fmt.Errorf("authorization mismatch: bad request")
	}

	return &tk, nil
}

// AuthMiddleware returns a Gin middleware that authenticates requests via cookie or AWS HMAC.
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		var (
			userName string
			subject  string
		)
		authHead := c.Request.Header.Get("Authorization")
		if authHead == "" {
			store, err := session.Start(c.Request.Context(), c.Writer, c.Request)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				c.Abort()
				return
			}

			user, ok := store.Get("LoggedInUserID")
			if !ok || user == "" {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
				return
			}
			subject = fmt.Sprintf("users:%s", user)
			userName = user.(string)
		} else {
			tk, err := checkAWSHMAC(c.Request)
			if err != nil {
				log.Println("[Err] AWS HMAC verification failed:", err)
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "bad AWS4-HMAC-SHA256"})
				return
			}
			subject = fmt.Sprintf("tokens:%s", tk.AccessKey)
			userName = tk.UserName
		}
		c.Set("UserName", userName)
		c.Set("Subject", subject)
	}
}

// handleTokenAuth processes token-based authentication.
func handleTokenAuth(c *gin.Context, req TokenAuthRequest) {
	tk, err := doAuthToken(req)
	if err != nil {
		log.Println("[Err] token auth failed:", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error":     "auth failed",
			"message":   err.Error(),
			"request":   req,
		})
		return
	}
	c.JSON(http.StatusOK, tk)
}

// handleCookieAuth processes cookie-based authentication.
func handleCookieAuth(c *gin.Context) {
	store, err := session.Start(c.Request.Context(), c.Writer, c.Request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	subject, ok := store.Get("LoggedInUserID")
	if !ok || subject == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"UserName": subject})
}

// doAuthToken validates and returns an access token.
func doAuthToken(req TokenAuthRequest) (models.AccessToken, error) {
	var tk models.AccessToken

	if err := tk.FindByAccessKey(req.AccessKey); err != nil {
		return tk, err
	}

	t, err := time.Parse(sign4.BasicDateFormat, req.Timestamp)
	if err != nil {
		return tk, fmt.Errorf("invalid timestamp: %w", err)
	}

	signingKey, err := sign4.GenerateSigningKey(tk.SecretKey, req.Region, req.Service, t)
	if err != nil {
		return tk, fmt.Errorf("failed to generate signing key: %w", err)
	}

	signature, err := sign4.SignStringToSign(req.VerifyData, signingKey)
	if err != nil {
		return tk, fmt.Errorf("failed to sign data: %w", err)
	}

	if signature != req.Signature {
		return tk, fmt.Errorf("signature mismatch")
	}

	tk.SecretKey = "hidden"

	return tk, nil
}

// TokenAuth handles the /authentication endpoint, routing to token or cookie auth.
func TokenAuth(c *gin.Context) {
	var req TokenAuthRequest
	err := c.BindJSON(&req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}

	if strings.ToLower(req.RequestType) == "token" {
		handleTokenAuth(c, req)
		return
	}

	if strings.ToLower(req.RequestType) == "cookie" {
		handleCookieAuth(c)
		return
	}

	c.JSON(http.StatusBadRequest, gin.H{"error": "auth type error"})
}
