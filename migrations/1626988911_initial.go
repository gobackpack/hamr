package migrations

import (
	"github.com/gobackpack/hamr/models"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// Initial migration
type Initial struct{}

// Apply migration
func (mig *Initial) Apply(db *gorm.DB) error {
	logrus.Info("Applying [initial] migration")

	return db.AutoMigrate(&models.User{})
}

// Timestamp when migration was created
func (mig *Initial) Timestamp() int64 {
	return int64(1626988911)
}

// Name of migration
func (mig *Initial) Name() string {
	return "Initial"
}
