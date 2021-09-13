package cache

import "time"

type Item struct {
	Key        string
	Value      interface{}
	Expiration time.Duration
}

type Storage interface {
	Store(items ...*Item) error
	Get(keys ...string) ([]byte, error)
	Delete(keys ...string) error
}
