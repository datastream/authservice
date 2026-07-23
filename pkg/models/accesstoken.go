package models

import (
	"context"
	"fmt"
	"time"

	"github.com/datastream/authservice/pkg/db"
)

// AccessToken is an AWS HMAC auth token.
type AccessToken struct {
	ID        int32
	UserName  string
	AccessKey string
	SecretKey string
	Describe  *string
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

// FindByAccessKey finds an access token by access key.
func (a *AccessToken) FindByAccessKey(ak string) error {
	if querier == nil {
		return fmt.Errorf("models: database queries not initialized")
	}
	t, err := querier.GetAccessTokenByAccessKey(context.Background(), ak)
	if err != nil {
		return err
	}
	*a = toAccessToken(t)
	return nil
}

func toAccessToken(t db.AccessToken) AccessToken {
	return AccessToken{
		ID:        int32(t.ID),
		UserName:  db.InterfaceToString(t.UserName),
		AccessKey: db.InterfaceToString(t.AccessKey),
		SecretKey: db.InterfaceToString(t.SecretKey),
		Describe:  db.NullStringToString(t.Describe),
		CreatedAt: t.CreatedAt,
		UpdatedAt: t.UpdatedAt,
		DeletedAt: db.NullTimeToTimePtr(t.DeletedAt),
	}
}
