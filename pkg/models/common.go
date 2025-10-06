package models

import (
	"log"
	"sync"

	"gorm.io/gorm"
)

var once sync.Once

var DB *gorm.DB

// Register is a function that registers a function with the database.
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
