package models

import (
	"time"

	"gorm.io/gorm"
)

// Tokens setting
type AccessToken struct {
	UserName  string    `json:"userName" gorm:"index"`
	AccessKey string    `json:"accessKey" gorm:"uniqueIndex:access_key,secret_key"`
	SecretKey string    `json:"secretKey" gorm:"uniqueIndex:access_key,secret_key"`
	Describe  string    `json:"describe"`
	CreatedAt time.Time `json:"createdAt" gorm:"autoCreateTime"`
	UpdatedAt time.Time `json:"updatedAt" gorm:"autoUpdateTime"`
	DeletedAt gorm.DeletedAt
	ID        int `json:"id" gorm:"primaryKey"`
}

func (t *AccessToken) FindByAccessKey(ak string) error {
	return DB.Where("access_key = ?", ak).First(t).Error
}
