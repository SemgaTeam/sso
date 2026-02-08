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
	"database/sql"
	"log"
)

func main() {
	dsn := "postgres://postgres:password@db:5432/postgres"

	ctx := context.Background()

	sqlDb, err := sql.Open("pgx", dsn)
	if err != nil {
		log.Fatal(err)
	}

	if err := goose.Up(sqlDb, "migrations"); err != nil {
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

	signingKey := "secret"
	signingMethod := jwt.SigningMethodHS256

	accessTokenExpiration := 3600
	refreshTokenExpiration := 60*60*24*7
	
	clientInterface := infrastructure.NewClientInterface(pool)
	tokenInterface := infrastructure.NewTokenInterface(signingKey, signingMethod)
	userInterface := infrastructure.NewUserInterface(pool)
	hashInterface := infrastructure.NewHashInterface(10)
	keysInterface := infrastructure.NewKeyInterface()

	oauthWorkflow := core.NewOAuthWorkflow(clientInterface, tokenInterface, keysInterface, accessTokenExpiration, refreshTokenExpiration)

	loginUC := core.NewLoginUseCase(userInterface, tokenInterface, hashInterface)
	registerUC := core.NewRegisterUseCase(userInterface, tokenInterface, hashInterface)
	userUC := core.NewUserUseCase(userInterface)
	jwksUC := core.NewJWKSUseCase(keysInterface)

	e := echo.New()

	http.SetupHandlers(e, pool, userUC, loginUC, registerUC, oauthWorkflow, jwksUC)	

	e.Logger.Fatal(e.Start(":8080"))
}
