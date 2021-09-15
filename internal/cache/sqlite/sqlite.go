package sqlite

import (
	"encoding/json"
	"errors"
	"github.com/gobackpack/hamr/internal/cache"
	"github.com/gobackpack/hamr/internal/env"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"strings"
	"time"
)

type Storage struct {
	Db *gorm.DB
}

type token struct {
	Id         uint `gorm:"primarykey"`
	Key        string
	Value      string
	Expiration time.Time
}

func Initialize(fallbackDbName string) (*Storage, error) {
	connString := env.Get("db_conn_string", fallbackDbName)
	if strings.TrimSpace(connString) == "" {
		return nil, errors.New("missing connection string")
	}

	db, err := gorm.Open(sqlite.Open(connString), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		return nil, err
	}

	if err = db.AutoMigrate(&token{}); err != nil {
		return nil, err
	}

	return &Storage{
		Db: db,
	}, nil
}

func (storage *Storage) Store(items ...*cache.Item) error {
	var tokensData []*token

	for _, i := range items {
		data, err := json.Marshal(i.Value)
		if err != nil {
			return err
		}

		tokensData = append(tokensData, &token{
			Key:        i.Key,
			Value:      string(data),
			Expiration: time.Now().Add(i.Expiration),
		})
	}

	if result := storage.Db.Model(&token{}).Create(tokensData); result.Error != nil {
		return result.Error
	}

	return nil
}

func (storage *Storage) Get(key string) ([]byte, error) {
	var tokensData *token

	if result := storage.Db.Where("key", key).Find(&tokensData); result.Error != nil {
		return nil, result.Error
	}

	if tokensData.Id == 0 {
		return nil, errors.New("key does not exist")
	}

	if tokensData.Expiration.Before(time.Now().UTC()) {
		return nil, errors.New("token expired")
	}

	return []byte(tokensData.Value), nil
}

func (storage *Storage) Delete(keys ...string) error {
	for _, key := range keys {
		if result := storage.Db.Model(&token{}).Where("key", key).Delete(&key); result.Error != nil {
			return result.Error
		}
	}

	return nil
}
