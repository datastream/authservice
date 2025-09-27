package models

import (
	"context"
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
