package env

import "os"

func Get(env, def string) string {
	e := os.Getenv(env)

	if e == "" {
		e = def
	}

	return e
}
