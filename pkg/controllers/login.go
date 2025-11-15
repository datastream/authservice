package controllers

import (
	"context"
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
	store, err := session.Start(context.TODO(), c.Writer, c.Request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if _, ok := store.Get("LoggedInUserID"); ok {
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
	issuer := fmt.Sprintf("%s://%s", c.Request.URL.Scheme, c.Request.Host)
	config := map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oauth2/authorize",
		"token_endpoint":                        issuer + "/oauth2/token",
		"userinfo_endpoint":                     issuer + "/userinfo",
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}
	c.JSON(http.StatusOK, config)
}
