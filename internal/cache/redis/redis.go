package redis

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gobackpack/hamr/internal/cache"
	"strings"

	"github.com/go-redis/redis"
)

// pipeLength defines limit whether to use pipeline or not
const pipeLength = 1

type Storage struct {
	*redis.Client
	*Config
}

type Config struct {
	Host       string
	Port       string
	Password   string
	DB         int
	PipeLength int
}

func NewConfig() *Config {
	return &Config{
		Host:     "",
		Port:     "",
		Password: "",
		DB:       0,
	}
}

func (storage *Storage) Initialize() error {
	client := redis.NewClient(&redis.Options{
		Addr:     storage.Config.Host + ":" + storage.Config.Port,
		Password: storage.Config.Password, // no password set
		DB:       storage.Config.DB,       // use default DB
	})

	if storage.Config.PipeLength == 0 {
		storage.Config.PipeLength = pipeLength
	}

	_, err := client.Ping().Result()
	if err != nil {
		return err
	}

	storage.Client = client

	return nil
}

func (storage *Storage) Store(items ...*cache.Item) error {
	if len(items) > storage.PipeLength { // with pipeline
		pipe := storage.Client.Pipeline()

		for _, item := range items {
			itemBytes, err := json.Marshal(item.Value)
			if err != nil {
				return err
			}

			pipe.Set(item.Key, string(itemBytes), item.Expiration)
		}

		_, err := pipe.Exec()
		if err != nil {
			return err
		}
	} else { // without pipeline
		var errMsgs []string

		for _, item := range items {
			itemBytes, err := json.Marshal(item.Value)
			if err != nil {
				return err
			}

			if err = storage.Client.Set(item.Key, string(itemBytes), item.Expiration).Err(); err != nil {
				errMsgs = append(errMsgs, err.Error())
			}
		}

		if len(errMsgs) > 0 {
			return errors.New(strings.Join(errMsgs, ","))
		}
	}

	return nil
}

func (storage *Storage) Get(key string) ([]byte, error) {
	cacheValue, err := storage.Client.Get(key).Result()

	switch {
	// key does not exist
	case err == redis.Nil:
		return nil, errors.New(fmt.Sprintf("key %v does not exist", key))
	// some other error
	case err != nil:
		return nil, err
	}

	return []byte(cacheValue), nil
}

func (storage *Storage) Delete(keys ...string) error {
	return storage.Client.Del(keys...).Err()
}
