package models

import (
	"context"
	"fmt"
	"time"

	"github.com/datastream/authservice/pkg/db"
	"golang.org/x/crypto/bcrypt"
)

// User is a user account.
type User struct {
	ID             int32
	Username       string
	HashedPassword []byte
	Email          *string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt      *time.Time
}

// NewUser creates a new User from form data.
func NewUser(username, email string) *User {
	return &User{Username: username, Email: ptrString(email)}
}

func ptrString(s string) *string { return &s }

// FindUserByUsername finds a user by username.
func FindUserByUsername(username string) (*User, error) {
	if querier == nil {
		return nil, fmt.Errorf("models: database queries not initialized")
	}
	u, err := querier.GetUserByUsername(context.Background(), username)
	if err != nil {
		return nil, err
	}
	return dbUserToUser(u), nil
}

// Save persists the user (INSERT).
func (u *User) Save() error {
	if querier == nil {
		return fmt.Errorf("models: database queries not initialized")
	}
	return querier.CreateUser(context.Background(), db.CreateUserParams{
		Username:       u.Username,
		HashedPassword: u.HashedPassword,
		Email:          db.ToNullString(u.Email),
	})
}

// GenHashedPassword hashes the provided password.
func (u *User) GenHashedPassword(password string) error {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.HashedPassword = hashed
	return nil
}

// CheckPassword compares the provided password against the hashed password.
func (u *User) CheckPassword(password string) error {
	return bcrypt.CompareHashAndPassword(u.HashedPassword, []byte(password))
}

func dbUserToUser(u db.User) *User {
	return &User{
		ID:             u.ID,
		Username:       u.Username,
		HashedPassword: u.HashedPassword,
		Email:          db.NullStringToString(u.Email),
		CreatedAt:      u.CreatedAt,
		UpdatedAt:      u.UpdatedAt,
		DeletedAt:      db.NullTimeToTimePtr(u.DeletedAt),
	}
}
