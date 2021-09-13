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
			pipe.Set(item.Key, item.Value, item.Expiration)
		}

		_, err := pipe.Exec()
		if err != nil {
			return err
		}
	} else { // without pipeline
		var errMsgs []string

		for _, item := range items {
			if err := storage.Client.Set(item.Key, item.Value, item.Expiration).Err(); err != nil {
				errMsgs = append(errMsgs, err.Error())
			}
		}

		if len(errMsgs) > 0 {
			return errors.New(strings.Join(errMsgs, ","))
		}
	}

	return nil
}

func (storage *Storage) Get(keys ...string) ([]byte, error) {
	var result []byte

	if len(keys) > storage.PipeLength { // with pipeline
		pipe := storage.Client.Pipeline()

		for _, key := range keys {
			pipe.Get(key)
		}

		res, err := pipe.Exec()
		if err != nil {
			return nil, err
		}

		var itemsToReturn [][]byte
		for _, item := range res {
			itemsToReturn = append(itemsToReturn, []byte(item.(*redis.StringCmd).Val()))
		}

		itemsByte, err := json.Marshal(itemsToReturn)
		if err != nil {
			return nil, err
		}

		result = itemsByte
	} else { // without pipeline
		var errMsgs []string

		for _, key := range keys {
			val, err := storage.Client.Get(key).Result()

			switch {
			// key does not exist
			case err == redis.Nil:
				errMsgs = append(errMsgs, fmt.Sprintf("key %v does not exist", key))
			// some other error
			case err != nil:
				errMsgs = append(errMsgs, err.Error())
			// no errors
			default:
				result = []byte(val)
			}
		}

		if len(errMsgs) > 0 {
			return result, errors.New(strings.Join(errMsgs, ","))
		}
	}

	return result, nil
}

func (storage *Storage) Delete(keys ...string) error {
	return storage.Client.Del(keys...).Err()
}
