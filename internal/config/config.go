package config

import (
	"os"
)

type Config struct {
	AppPort string

	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURL  string

	RedisAddr     string
	RedisPassword string

	DatabaseDSN string
}

func Load() Config {

	cfg := Config{

		AppPort: os.Getenv("APP_PORT"),

		GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		GoogleRedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),

		RedisAddr:     os.Getenv("REDIS_ADDR"),
		RedisPassword: os.Getenv("REDIS_PASSWORD"),

		DatabaseDSN: os.Getenv("DATABASE_DSN"),
	}

	return cfg

}
