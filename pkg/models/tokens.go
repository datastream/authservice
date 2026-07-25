package models

import (
	"context"
	"time"

	"github.com/datastream/authservice/pkg/db"
)

// Token is an OAuth client.
type Token struct {
	ID           int32      `json:"id"`
	UserID       string     `json:"userId"`
	ClientID     string     `json:"clientId"`
	ClientSecret string     `json:"clientSecret"`
	Domain       string     `json:"domain"`
	Public       bool       `json:"public"`
	Description  *string    `json:"description"`
	RedirectURIs *string    `json:"redirectUris"`
	CreatedAt    time.Time  `json:"createdAt"`
	UpdatedAt    time.Time  `json:"updatedAt"`
	DeletedAt    *time.Time `json:"deletedAt"`
}

// FindTokenByClientID finds a token by client ID.
// Returns ErrDBNotInitialized if the database is not ready, or the underlying
// query error (typically sql.ErrNoRows when the client doesn't exist).
func FindTokenByClientID(id string) (*Token, error) {
	if querier == nil {
		return nil, ErrDBNotInitialized
	}
	t, err := querier.GetTokenByClientID(context.Background(), id)
	if err != nil {
		return nil, err
	}
	return toToken(&t), nil
}

// FindTokensByUserID finds tokens by user ID.
func FindTokensByUserID(userID string) ([]Token, error) {
	if querier == nil {
		return nil, ErrDBNotInitialized
	}
	ts, err := querier.GetTokensByUserID(context.Background(), userID)
	if err != nil {
		return nil, err
	}
	tokens := make([]Token, len(ts))
	for i, t := range ts {
		tokens[i] = *toToken(&t)
	}
	return tokens, nil
}

// FindTokensByDomain finds tokens by domain.
func FindTokensByDomain(host string) ([]Token, error) {
	if querier == nil {
		return nil, ErrDBNotInitialized
	}
	ts, err := querier.GetTokensByDomain(context.Background(), host)
	if err != nil {
		return nil, err
	}
	tokens := make([]Token, len(ts))
	for i, t := range ts {
		tokens[i] = *toToken(&t)
	}
	return tokens, nil
}

// FindTokensByDisplayDomain finds tokens by display domain.
func FindTokensByDisplayDomain(domain string) ([]Token, error) {
	return FindTokensByDomain(domain)
}

// Save persists the token (INSERT).
// Returns ErrDBNotInitialized if the database is not ready, or the underlying
// query error (e.g. unique constraint violation).
// On success, populates t.ID with the auto-generated primary key.
func (t *Token) Save() error {
	if querier == nil {
		return ErrDBNotInitialized
	}
	// Generate IDs if not set
	if t.ClientID == "" {
		id, err := db.GenerateRandomString(32)
		if err != nil {
			return err
		}
		t.ClientID = id
	}
	if t.ClientSecret == "" {
		secret, err := db.GenerateRandomString(64)
		if err != nil {
			return err
		}
		t.ClientSecret = secret
	}
	id, err := querier.CreateToken(context.Background(), db.CreateTokenParams{
		UserID:       t.UserID,
		ClientID:     t.ClientID,
		ClientSecret: t.ClientSecret,
		Domain:       t.Domain,
		Public:       db.BoolToInt64(t.Public),
		RedirectUris: db.ToNullString(t.RedirectURIs),
	})
	if err != nil {
		return err
	}
	t.ID = id
	return nil
}

// Delete removes the token.
func (t *Token) Delete() error {
	if querier == nil {
		return ErrDBNotInitialized
	}
	return querier.DeleteToken(context.Background(), t.ClientID)
}

// UpdateRedirectURIs atomically updates redirect URIs.
func UpdateRedirectURIs(clientID string, uris *string) error {
	if querier == nil {
		return ErrDBNotInitialized
	}
	return querier.UpdateRedirectURIs(context.Background(), db.UpdateRedirectURIsParams{
		ClientID:     clientID,
		RedirectUris: db.ToNullString(uris),
	})
}

func toToken(t *db.Token) *Token {
	id := db.InterfaceToInt64(t.ID)
	return &Token{
		ID:           int32(id),
		UserID:       db.InterfaceToString(t.UserID),
		ClientID:     db.InterfaceToString(t.ClientID),
		ClientSecret: db.InterfaceToString(t.ClientSecret),
		Domain:       db.InterfaceToString(t.Domain),
		Public:       db.Int64ToBool(t.Public),
		Description:  db.NullStringToString(t.Description),
		RedirectURIs: db.NullStringToString(t.RedirectUris),
		CreatedAt:    t.CreatedAt,
		UpdatedAt:    t.UpdatedAt,
		DeletedAt:    db.NullTimeToTimePtr(t.DeletedAt),
	}
}
