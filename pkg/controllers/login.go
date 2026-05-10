// Package controllers provides HTTP handlers for the OAuth service using the Gin framework.
// It includes controllers for login, OAuth authorization, token management, and FGA integration.
package controllers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/datastream/authservice/pkg/middleware"
	"github.com/datastream/authservice/pkg/models"
	sign4 "github.com/datastream/aws"
	"github.com/gin-gonic/gin"
	"github.com/go-session/session/v3"
	"log"
)

// LoginForm represents the login form fields.
type LoginForm struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" binding:"required"`
}

// LoginPageData holds data for rendering the login page.
type LoginPageData struct {
	Domain   string
	LoginURL string
}

// LoginPage serves the login page.
func LoginPage(c *gin.Context) {
	// If already logged in, redirect to /userinfo.
	_, ok, err := middleware.GetLoggedInUserID(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if ok {
		c.Header("Location", "/userinfo")
		c.JSON(http.StatusFound, gin.H{"message": "Logged in", "redirect": "/auth"})
		return
	}
	token, err := models.FindTokenByClientID(c.Query("client_id"))
	loginData := LoginPageData{
		LoginURL: c.Request.RequestURI,
		Domain:   c.Request.Host,
	}
	if err == nil {
		loginData.Domain = token.Domain
	}
	if err := middleware.ServeStaticHTML(c, "login.html"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load login page"})
		return
	}
}

// Logout logs out the current user by clearing their session.
func Logout(c *gin.Context) {
	store, err := session.Start(c.Request.Context(), c.Writer, c.Request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	store.Flush()
	err = store.Save()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// redirect to /login
	c.Header("Location", "/login")
	c.JSON(http.StatusFound, gin.H{"message": "Logout successful", "redirect": "/login"})
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
	config := map[string]interface{}{
		"issuer":                   issuer,
		"authorization_endpoint":   issuer + "/oauth/authorize",
		"token_endpoint":           issuer + "/oauth/token",
		"userinfo_endpoint":        issuer + "/userinfo",
		"scopes_supported":         []string{"openid", "profile", "email"},
		"response_types_supported": []string{"code", "code token"},
	}
	c.JSON(http.StatusOK, config)
}
