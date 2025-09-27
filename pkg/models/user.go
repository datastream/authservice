package models

import (
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	Username       string    `json:"username" gorm:"primaryKey"`
	HashedPassword []byte    `json:"-"`
	Email          string    `json:"email"`
	CreatedAt      time.Time `json:"createdAt" gorm:"autoCreateTime"`
	UpdatedAt      time.Time `json:"updatedAt" gorm:"autoUpdateTime"`
	DeletedAt      gorm.DeletedAt
	ID             int `json:"id" gorm:"primaryKey"`
}

func (u *User) BeforeSave(tx *gorm.DB) (err error) {
	if len(u.HashedPassword) > 0 { // Only hash if a new password is set or updated
		hashedPassword, err := bcrypt.GenerateFromPassword(u.HashedPassword, bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		u.HashedPassword = hashedPassword
	}
	return nil
}
func CheckPassword(storedHashedPassword []byte, providedPassword string) error {
	return bcrypt.CompareHashAndPassword(storedHashedPassword, []byte(providedPassword))
}
