package models

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
	"gorm.io/gorm"
)

// Tokens setting
type Token struct {
	UserID       string    `json:"userID" gorm:"index"`
	ClientID     string    `json:"clientID" gorm:"uniqueIndex:client_id"`
	ClientSecret string    `json:"clientSecret"`
	Domain       string    `json:"domain"`
	Public       bool      `json:"public"`
	Describe     string    `json:"describe"`
	CreatedAt    time.Time `json:"createdAt" gorm:"autoCreateTime"`
	UpdatedAt    time.Time `json:"updatedAt" gorm:"autoUpdateTime"`
	DeletedAt    gorm.DeletedAt
	ID           int `json:"id" gorm:"primaryKey"`
}

// save token
func (t *Token) Save() error {
	// generate client ID and secret if not set
	var err error
	if t.ClientID == "" {
		t.ClientID, err = GenerateRandomString(32)
	}
	if err != nil {
		return err
	}
	if t.ClientSecret == "" {
		t.ClientSecret, err = GenerateRandomString(64)
	}
	if err != nil {
		return err
	}
	return DB.FirstOrCreate(t, Token{ClientID: t.ClientID}).Error
}

func GenerateRandomString(n int) (string, error) {
	// Create a slice of n random bytes
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return "", errors.New("failed to generate random string")
	}

	// Optionally, you can base64 encode the result if you want a printable string
	// (but you can also just return raw bytes or use a different encoding).
	return base64.URLEncoding.EncodeToString(b)[:n], nil
}

// delete token
func (t *Token) Delete() error {
	return DB.Delete(t).Error
}

type ClientStore struct{}

// GetByID according to the ID for the client information
func (c *ClientStore) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	var token Token
	result := DB.Where("client_id = ?", id).First(&token)
	if result.Error != nil {
		return nil, result.Error
	}
	return &models.Client{
		ID:     token.ClientID,
		Secret: token.ClientSecret,
		Domain: token.Domain,
		UserID: token.UserID,
		Public: token.Public,
	}, nil
}

// FindTokensByUserID finds tokens by user ID
func FindTokensByUserID(userID string) ([]Token, error) {
	var tokens []Token
	result := DB.Where("user_id = ?", userID).Find(&tokens)
	if result.Error != nil {
		return nil, result.Error
	}
	return tokens, nil
}

// FindTokenByClientID finds a token by client ID
func FindTokenByClientID(clientID string) (*Token, error) {
	var token Token
	result := DB.Where("client_id = ?", clientID).First(&token)
	if result.Error != nil {
		return nil, result.Error
	}
	return &token, nil
}
