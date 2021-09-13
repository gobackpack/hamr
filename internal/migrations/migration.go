package migrations

import (
	"github.com/sirupsen/logrus"
	"sort"
	"time"

	"gorm.io/gorm"
)

// MigrationDefinition for each migration
type MigrationDefinition interface {
	Name() string
	Apply(*gorm.DB) error
	Timestamp() int64
}

// migration represents single row in migrations table
type migration struct {
	ID        uint `gorm:"primary_key"`
	Name      string
	Timestamp int64
	CreatedAt time.Time
}

// Run migrations collection
func Run(migrationsCollection []MigrationDefinition, db *gorm.DB) {
	tx := db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	if err := tx.Error; err != nil {
		logrus.Error(err)
		return
	}

	if err := tx.AutoMigrate(&migration{}); err != nil {
		logrus.Errorf("auto-migrate for migrations table failed: %v", err)
		tx.Rollback()
		return
	}

	sort.Slice(migrationsCollection, func(i, j int) bool {
		return migrationsCollection[i].Timestamp() < migrationsCollection[j].Timestamp()
	})

	migrations := getMigrationsHistory(tx)

	for _, migrationDefinition := range migrationsCollection {
		if !applied(migrationDefinition, migrations) {
			if err := migrationDefinition.Apply(tx); err != nil {
				logrus.Errorf("migration %s failed to apply: %v", migrationDefinition.Name(), err)
				tx.Rollback()
				break
			}

			if err := saveMigrationHistory(migrationDefinition, tx); err != nil {
				logrus.Warnf("failed to record migration %s: %v", migrationDefinition.Name(), err)
				tx.Rollback()
				break
			}

			logrus.Infof("migration %s applied", migrationDefinition.Name())
		}
	}

	if err := tx.Commit().Error; err != nil {
		logrus.Errorf("migrations failed: %v", err)
	}
}

func applied(mig MigrationDefinition, migrations []*migration) bool {
	for _, m := range migrations {
		if mig.Timestamp() == m.Timestamp {
			return true
		}
	}

	return false
}

func getMigrationsHistory(db *gorm.DB) []*migration {
	var migrations []*migration

	db.Find(&migrations)

	return migrations
}

func saveMigrationHistory(m MigrationDefinition, db *gorm.DB) error {
	return db.Create(&migration{
		Name:      m.Name(),
		Timestamp: m.Timestamp(),
	}).Error
}
