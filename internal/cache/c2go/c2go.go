package c2go

import (
	"encoding/json"
	"github.com/gobackpack/hamr/internal/cache"
	"github.com/muesli/cache2go"
)

type Storage struct {
	Engine *cache2go.CacheTable
}

func New(tableName string) *Storage {
	return &Storage{
		Engine: cache2go.Cache(tableName),
	}
}

func (storage *Storage) Store(items ...*cache.Item) error {
	for _, item := range items {
		storage.Engine.Add(item.Key, item.Expiration, item.Value)
	}

	return nil
}

func (storage *Storage) Get(keys ...string) ([]byte, error) {
	var result []byte

	for _, k := range keys {
		item, err := storage.Engine.Value(k)
		if err != nil {
			continue
		}

		bItem, err := json.Marshal(item.Data())
		if err != nil {
			continue
		}

		result = append(result, bItem...)
	}

	return result, nil
}

func (storage *Storage) Delete(keys ...string) error {
	for k := range keys {
		storage.Engine.Delete(k)
	}

	return nil
}
