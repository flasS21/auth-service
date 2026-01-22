package app

import (
	"context"
	"database/sql"

	"auth-service/internal/config"
	"auth-service/internal/db"
	"auth-service/internal/logger"
	"auth-service/internal/redis"

	_ "github.com/lib/pq"
)

type Infra struct {
	DB    *db.DB
	Redis *redis.Client
}

func setupInfra(ctx context.Context, cfg config.Config) (*Infra, error) {
	sqlDB, err := sql.Open("postgres", cfg.DatabaseDSN)
	if err != nil {
		return nil, err
	}

	if err := sqlDB.PingContext(ctx); err != nil {
		return nil, err
	}

	if err := db.RunKeystoneMigration(ctx, sqlDB); err != nil {
		return nil, err
	}

	logger.Info("database ready", nil)

	redisClient, err := redis.New(cfg.RedisAddr, cfg.RedisPassword)
	if err != nil {
		return nil, err
	}

	logger.Info("redis ready", nil)

	return &Infra{
		DB:    &db.DB{DB: sqlDB},
		Redis: redisClient,
	}, nil
}
