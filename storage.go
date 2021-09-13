package hamr

import (
	"github.com/gobackpack/hamr/internal/cache"
	"github.com/gobackpack/hamr/internal/cache/c2go"
	"github.com/gobackpack/hamr/internal/cache/redis"
	"github.com/gobackpack/hamr/internal/env"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlserver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"strings"
)

func PostgresDb(fallbackConnStr string) *gorm.DB {
	connString := env.Get("db_conn_string", fallbackConnStr)
	if strings.TrimSpace(connString) == "" {
		logrus.Error("missing connection string [env|config.yml]")
		logrus.Warn("CAUTION! service will be running without database connection!")
		return nil
	}

	db, err := gorm.Open(postgres.Open(connString), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		logrus.Error("failed to connect database: ", err)
		logrus.Warn("CAUTION! service will be running without database connection!")
	}

	return db
}

func MySqlDb(fallbackConnStr string) *gorm.DB {
	connString := env.Get("db_conn_string", fallbackConnStr)
	if strings.TrimSpace(connString) == "" {
		logrus.Error("missing connection string [env|config.yml]")
		logrus.Warn("CAUTION! service will be running without database connection!")
		return nil
	}

	db, err := gorm.Open(mysql.Open(connString), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		logrus.Error("failed to connect database: ", err)
		logrus.Warn("CAUTION! service will be running without database connection!")
	}

	return db
}

func SqlServerDb(fallbackConnStr string) *gorm.DB {
	connString := env.Get("db_conn_string", fallbackConnStr)
	if strings.TrimSpace(connString) == "" {
		logrus.Error("missing connection string [env|config.yml]")
		logrus.Warn("CAUTION! service will be running without database connection!")
		return nil
	}

	db, err := gorm.Open(sqlserver.Open(connString), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		logrus.Error("failed to connect database: ", err)
		logrus.Warn("CAUTION! service will be running without database connection!")
	}

	return db
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
