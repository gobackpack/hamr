package models

import (
	"gorm.io/gorm"
	"time"
)

// User of the system
type User struct {
	Id               uint `gorm:"primarykey"`
	Username         string
	Email            string
	Password         string `json:"-"`
	ExternalId       string
	ExternalProvider string
	Confirmed        bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
	DeletedAt        gorm.DeletedAt `gorm:"index"`
}
