package main

import (
	"sso/internal/core"
	"sso/internal/infrastructure"
	"sso/internal/infrastructure/http"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/labstack/echo/v4"
	"github.com/pressly/goose/v3"

	"context"
	"strconv"
	"database/sql"
	"log"
	"os"
)

func main() {
	dsn := os.Getenv("POSTGRES_URL")
	if dsn == "" {
		log.Fatal("POSTGRES_URL is not set")
	}

	migrationsPath := os.Getenv("MIGRATIONS_PATH")
	if migrationsPath == "" {
		migrationsPath = "migrations"
	}

	signingKey := os.Getenv("SIGNING_KEY")
	if signingKey == "" {
		log.Fatal("SIGNING_KEY is not set")
	}
	signingMethod := jwt.SigningMethodHS256

	accessExpirationStr := os.Getenv("ACCESS_TOKEN_EXPIRATION")
	if accessExpirationStr == "" {
		log.Fatal("ACCESS_TOKEN_EXPIRATION is not set")
	}
	accessTokenExpiration, err := strconv.Atoi(accessExpirationStr)
	if err != nil {
		log.Fatal(err)
	}

	refreshExpirationStr := os.Getenv("REFRESH_TOKEN_EXPIRATION")
	if refreshExpirationStr == "" {
		log.Fatal("REFRESH_TOKEN_EXPIRATION is not set")
	}
	refreshTokenExpiration, err := strconv.Atoi(refreshExpirationStr)
	if err != nil {
		log.Fatal(err)
	}

	hashCost := 10

	ctx := context.Background()

	sqlDb, err := sql.Open("pgx", dsn)
	if err != nil {
		log.Fatal(err)
	}

	if err := goose.Up(sqlDb, migrationsPath); err != nil {
		log.Fatal(err)
	}
	sqlDb.Close()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		log.Fatal(err)
	}

	log.Println("Connected to postgres")
	
	clientInterface := infrastructure.NewClientInterface(pool)
	tokenInterface := infrastructure.NewTokenInterface(signingKey, signingMethod)
	userInterface := infrastructure.NewUserInterface(pool)
	hashInterface := infrastructure.NewHashInterface(hashCost)
	keysInterface := infrastructure.NewKeyInterface()

	privateKey, err := keysInterface.Generate("test_key")
	if err != nil {
		panic("error generating private key " + err.Error())
	}
	keysInterface.SavePrivateKey(privateKey)

	oauthWorkflow := core.NewOAuthWorkflow(clientInterface, tokenInterface, keysInterface, accessTokenExpiration, refreshTokenExpiration)

	loginUC := core.NewLoginUseCase(userInterface, tokenInterface, hashInterface)
	registerUC := core.NewRegisterUseCase(userInterface, tokenInterface, hashInterface)
	userUC := core.NewUserUseCase(userInterface)
	jwksUC := core.NewJWKSUseCase(keysInterface)

	e := echo.New()

	http.SetupHandlers(e, userUC, loginUC, registerUC, oauthWorkflow, jwksUC)	

	e.Logger.Fatal(e.Start(":8080"))
}
