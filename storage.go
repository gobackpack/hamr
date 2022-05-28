package hamr

import (
	"github.com/gobackpack/hamr/internal/cache"
	"github.com/gobackpack/hamr/internal/cache/c2go"
	"github.com/gobackpack/hamr/internal/cache/redis"
	"github.com/gobackpack/hamr/internal/cache/sqlite"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlserver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// helpers for initialization of different storage engines.
// Postgres, MySql, SqlServer, Redis, Cache2Go, Sqlite

func PostgresDb(connString string) (*gorm.DB, error) {
	return gorm.Open(postgres.Open(connString), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
}

func MySqlDb(connString string) (*gorm.DB, error) {
	return gorm.Open(mysql.Open(connString), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
}

func SqlServerDb(connString string) (*gorm.DB, error) {
	return gorm.Open(sqlserver.Open(connString), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
}

func NewRedisCacheStorage(host, port, password string, cacheDb int) cache.Storage {
	redisConfig := redis.NewConfig()
	redisConfig.Host = host
	redisConfig.Port = port
	redisConfig.Password = password
	redisConfig.DB = cacheDb

	redisConn := &redis.Storage{
		Config: redisConfig,
	}

	if err := redisConn.Initialize(); err != nil {
		logrus.Fatal("failed to initialize redis connection: ", err)
	}

	return redisConn
}

func NewC2GoCacheStorage(cacheDb string) cache.Storage {
	return c2go.New(cacheDb)
}

func NewSqliteCacheStorage(cacheDb string) cache.Storage {
	storage, err := sqlite.Initialize(cacheDb)
	if err != nil {
		logrus.Fatal(err)
	}

	return storage
}
