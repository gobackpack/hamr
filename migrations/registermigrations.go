package migrations

import (
	migrationsLib "github.com/gobackpack/hamr/internal/migrations"
	"gorm.io/gorm"
)

// Collection with all migrations
var Collection = []migrationsLib.MigrationDefinition{
	&Initial{},
}

func Run(migrationsCollection []migrationsLib.MigrationDefinition, db *gorm.DB) {
	migrationsLib.Run(migrationsCollection, db)
}
