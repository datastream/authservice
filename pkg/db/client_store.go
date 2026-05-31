package db

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
)

// ClientStore implements oauth2.ClientStore interface.
type ClientStore struct {
	*Queries
}

var _ oauth2.ClientStore = (*ClientStore)(nil)

// GetByID implements oauth2.ClientStore.
func (cs *ClientStore) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	if cs.Queries == nil {
		return nil, errors.New("database not initialized")
	}
	return cs.Queries.GetClientByID(ctx, id)
}

// GetClientByID implements oauth2.ClientStore interface.
func (q *Queries) GetClientByID(ctx context.Context, id string) (*models.Client, error) {
	token, err := q.GetTokenByClientID(ctx, id)
	if err != nil {
		return nil, err
	}
	return &models.Client{
		ID:     token.ClientID,
		Secret: token.ClientSecret,
		Domain: token.Domain,
		UserID: token.UserID,
		Public: token.Public,
	}, nil
}

// GenerateRandomString generates a random base64-encoded string of length n.
func GenerateRandomString(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return "", errors.New("failed to generate random string")
	}
	return base64.URLEncoding.EncodeToString(b)[:n], nil
}

