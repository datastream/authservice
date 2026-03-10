package controllers

import (
	"github.com/datastream/authservice/pkg/middleware"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/datastream/authservice/pkg/models"
	sign4 "github.com/datastream/aws"
	"github.com/gin-gonic/gin"
	"github.com/go-session/session/v3"
)

type LoginForm struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" binding:"required"`
}

type LoginPageData struct {
	Domain   string
	LoginURL string
}

// login page don't need to handle uri query params
func LoginPage(c *gin.Context) {
	_, ok, err := middleware.GetLoggedInUserID(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if ok { // user is logged in
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
	// render auth page
	t, err := template.ParseFiles("static/login.html")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load login page"})
		return
	}
	err = t.Execute(c.Writer, loginData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to render login page"})
		return
	}

}

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

// if type is cookie, verifydata is encrypt cookie token
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

const (
	TOKEN  string = "token"
	COOKIE string = "cookie"
)

// check cookie or token auth
func TokenAuth(c *gin.Context) {
	var req TokenAuthRequest
	err := c.BindJSON(&req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"Status": "bad request"})
		return
	}

	// Handle TOKEN authentication
	if req.RequestType == TOKEN {
		handleTokenAuth(c, req)
		return
	}

	// Handle COOKIE authentication
	if req.RequestType == COOKIE {
		handleCookieAuth(c)
		return
	}

	// Invalid RequestType
	c.JSON(http.StatusBadRequest, gin.H{"Status": "auth type error"})
}

// auth middleware
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		var (
			userName string
			subject  string
		)
		authHead := c.Request.Header.Get("Authorization")
		if authHead == "" {
			// handle cookie auth
			store, err := session.Start(c.Request.Context(), c.Writer, c.Request)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				c.Abort()
				return
			}

			// Get the subject from the session
			user, ok := store.Get("LoggedInUserID")
			if !ok || user == "" {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
				return
			}
			subject = fmt.Sprintf("users:%s", user)
			userName = user.(string)
		} else {
			// handle token auth
			tk, err := checkAWSHMAC(c.Request)
			if err != nil {
				log.Println("[Err] AWS HMAC verification failed:", err)
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"Status": "bad AWS4-HMAC-SHA256"})
				return
			}
			subject = fmt.Sprintf("tokens:%s", tk.AccessKey)
			userName = tk.UserName
		}
		c.Set("UserName", userName)
		c.Set("Subject", subject)
	}
}
func checkAWSHMAC(r *http.Request) (*models.AccessToken, error) {
	// Extract the signature, auth string, and signed headers from the request
	s, authString, signedHeaders, err := sign4.GetSignature(r)
	if err != nil {
		return nil, fmt.Errorf("failed to get signature: %w", err)
	}

	// Find the token by AccessKey
	var tk models.AccessToken
	if err := tk.FindByAccessKey(s.AccessKey); err != nil {
		return nil, fmt.Errorf("failed to find token by access key: %w", err)
	}

	// Set the secret key from the token
	s.SecretKey = tk.SecretKey

	// Sign the request with the extracted signature
	if err := s.SignRequest(r, signedHeaders); err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	// Validate the Authorization header
	if authString != r.Header.Get("Authorization") {
		r.Header.Set("Authorization", authString)
		return nil, errors.New("authorization mismatch: bad request")
	}

	return &tk, nil
}
func handleTokenAuth(c *gin.Context, req TokenAuthRequest) {
	tk, err := doAuthToken(req)
	if err != nil {
		log.Println("[Err] token auth failed:", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"Status":  "auth failed",
			"message": err.Error(),
			"request": req,
		})
		return
	}
	c.JSON(http.StatusOK, tk)
}

// cookie auth must via https
func handleCookieAuth(c *gin.Context) {
	store, err := session.Start(c.Request.Context(), c.Writer, c.Request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Get the subject from the session
	subject, ok := store.Get("LoggedInUserID")
	if !ok || subject == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"UserName": subject})
}

func doAuthToken(req TokenAuthRequest) (models.AccessToken, error) {
	var tk models.AccessToken

	// Find the token by AccessKey
	if err := tk.FindByAccessKey(req.AccessKey); err != nil {
		return tk, err
	}

	// Parse the timestamp
	t, err := time.Parse(sign4.BasicDateFormat, req.Timestamp)
	if err != nil {
		return tk, fmt.Errorf("invalid timestamp: %w", err)
	}

	// Generate the signing key
	signingKey, err := sign4.GenerateSigningKey(tk.SecretKey, req.Region, req.Service, t)
	if err != nil {
		return tk, fmt.Errorf("failed to generate signing key: %w", err)
	}

	// Sign the string to sign
	signature, err := sign4.SignStringToSign(req.VerifyData, signingKey)
	if err != nil {
		return tk, fmt.Errorf("failed to sign data: %w", err)
	}

	// Verify the signature
	if signature != req.Signature {
		return tk, fmt.Errorf("signature mismatch")
	}

	// Hide the secret key before returning
	tk.SecretKey = "hidden"

	return tk, nil
}

func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	// Create a new AES cipher block using the provided key
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create a new GCM cipher mode
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext is too short")
	}

	// Split the nonce and the actual ciphertext
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt the ciphertext
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ciphertext: %w", err)
	}

	return plaintext, nil
}

// openid configuration endpoint
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
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oauth/authorize",
		"token_endpoint":                        issuer + "/oauth/token",
		"userinfo_endpoint":                     issuer + "/userinfo",
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"response_types_supported":              []string{"code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}
	c.JSON(http.StatusOK, config)
}
