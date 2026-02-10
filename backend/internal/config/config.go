package config

import (
	"github.com/golang-jwt/jwt/v5"

	"errors"
	"strconv"
	"os"
)

type Config struct {
	PostgresURL string
	MigrationsPath string
	SigningKey string
	SigningMethod jwt.SigningMethod
	AccessTokenExp int
	RefreshTokenExp int
	SessionExp int
	HashCost int
}

func GetConfig() (*Config, error) {
	dsn := os.Getenv("POSTGRES_URL")
	if dsn == "" {
		return nil, errors.New("POSTGRES_URL is not set")
	}

	migrationsPath := os.Getenv("MIGRATIONS_PATH")
	if migrationsPath == "" {
		migrationsPath = "migrations"
	}

	signingKey := os.Getenv("SIGNING_KEY")
	if signingKey == "" {
		return nil, errors.New("SIGNING_KEY is not set")
	}

	signingMethod := jwt.SigningMethodHS256

	accessExpirationStr := os.Getenv("ACCESS_TOKEN_EXPIRATION")
	if accessExpirationStr == "" {
		return nil, errors.New("ACCESS_TOKEN_EXPIRATION is not set")
	}
	accessTokenExpiration, err := strconv.Atoi(accessExpirationStr)
	if err != nil {
		return nil, err
	}

	refreshExpirationStr := os.Getenv("REFRESH_TOKEN_EXPIRATION")
	if refreshExpirationStr == "" {
		return nil, errors.New("REFRESH_TOKEN_EXPIRATION is not set")
	}
	refreshTokenExpiration, err := strconv.Atoi(refreshExpirationStr)
	if err != nil {
		return nil, err
	}

	sessionExpStr := os.Getenv("SESSION_EXPIRATION")
	if sessionExpStr == "" {
		return nil, errors.New("SESSION_EXPIRATION is not set")
	}
	sessionExp, err := strconv.Atoi(sessionExpStr)
	if err != nil {
		return nil, err
	}

	hashCost := 10

	conf := Config{
		PostgresURL: dsn,
		MigrationsPath: migrationsPath,
		SigningKey: signingKey, 
		SigningMethod: signingMethod,
		AccessTokenExp: accessTokenExpiration, 
		RefreshTokenExp: refreshTokenExpiration,
		SessionExp: sessionExp,
		HashCost: hashCost,
	}

	return &conf, nil
}
