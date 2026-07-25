package models

import (
	"context"
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
// Returns ErrDBNotInitialized if the database is not ready, or the underlying
// query error (typically sql.ErrNoRows when the user doesn't exist).
func FindUserByUsername(username string) (*User, error) {
	if querier == nil {
		return nil, ErrDBNotInitialized
	}
	u, err := querier.GetUserByUsername(context.Background(), username)
	if err != nil {
		return nil, err
	}
	return dbUserToUser(u), nil
}

// Save persists the user (INSERT).
// Returns ErrDBNotInitialized if the database is not ready, or the underlying
// query error (e.g. unique constraint violation on duplicate username).
// On success, populates u.ID with the auto-generated primary key.
func (u *User) Save() error {
	if querier == nil {
		return ErrDBNotInitialized
	}
	id, err := querier.CreateUser(context.Background(), db.CreateUserParams{
		Username:       u.Username,
		HashedPassword: u.HashedPassword,
		Email:          db.ToNullString(u.Email),
	})
	if err != nil {
		return err
	}
	u.ID = id
	return nil
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
	id := db.InterfaceToInt64(u.ID)
	return &User{
		ID:             int32(id),
		Username:       db.InterfaceToString(u.Username),
		HashedPassword: u.HashedPassword,
		Email:          db.NullStringToString(u.Email),
		CreatedAt:      u.CreatedAt,
		UpdatedAt:      u.UpdatedAt,
		DeletedAt:      db.NullTimeToTimePtr(u.DeletedAt),
	}
}
