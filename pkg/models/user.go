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

func (u *User) BeforeSave(password string) (err error) {
	if len(password) > 0 { // Only hash if a new password is set or updated
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		u.HashedPassword = hashedPassword
	}
	return nil
}
func (u *User) CheckPassword(providedPassword string) error {
	return bcrypt.CompareHashAndPassword(u.HashedPassword, []byte(providedPassword))
}
func (u *User) Save() error {
	return DB.FirstOrCreate(u).Error
}

func FindUserByUsername(username string) (*User, error) {
	var user User
	result := DB.Where("username = ?", username).First(&user)
	if result.Error != nil {
		return nil, result.Error
	}
	return &user, nil
}
