package cache

import "time"

type Item struct {
	Key        string
	Value      interface{}
	Expiration time.Duration
}

type Storage interface {
	Store(items ...*Item) error
	Get(key string) ([]byte, error)
	Delete(keys ...string) error
}
