// Package models defines the data models used by the auth service.
// It includes User, Token (OAuth client), and AccessToken (AWS HMAC auth) with
// GORM-backed persistence.
package models

import (
	"log"
	"sync"

	"gorm.io/gorm"
)

var once sync.Once

var DB *gorm.DB

// Register registers the database models with the given GORM instance.
// It auto-migrates Token and User schemas. This function is safe for
// concurrent use and only executes once.
func Register(db *gorm.DB) {
	once.Do(func() {
		if db == nil {
			log.Println("[Err] DB is nil, cannot register")
			return
		}

		DB = db
		if err := DB.AutoMigrate(&Token{}, &User{}); err != nil {
			log.Println("[Err] AutoMigrate failed:", err)
		}
	})
}
