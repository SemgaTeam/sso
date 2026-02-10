package main

import (
	"sso/internal/core"
	"sso/internal/config"
	"sso/internal/infrastructure"
	"sso/internal/infrastructure/http"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/labstack/echo/v4"
	"github.com/pressly/goose/v3"

	"context"
	"database/sql"
	"log"
)

func main() {
	conf, err := config.GetConfig()
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	sqlDb, err := sql.Open("pgx", conf.PostgresURL)
	if err != nil {
		log.Fatal(err)
	}

	if err := goose.Up(sqlDb, conf.MigrationsPath); err != nil {
		log.Fatal(err)
	}
	sqlDb.Close()

	pool, err := pgxpool.New(ctx, conf.PostgresURL)
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		log.Fatal(err)
	}

	log.Println("Connected to postgres")
	
	clientInterface := infrastructure.NewClientInterface(pool)
	tokenInterface := infrastructure.NewTokenInterface(conf.SigningKey, conf.SigningMethod)
	userInterface := infrastructure.NewUserInterface(pool)
	hashInterface := infrastructure.NewHashInterface(conf.HashCost)
	keysInterface := infrastructure.NewKeyInterface()

	privateKey, err := keysInterface.Generate("test_key")
	if err != nil {
		panic("error generating private key " + err.Error())
	}
	keysInterface.SavePrivateKey(privateKey)

	oauthWorkflow := core.NewOAuthWorkflow(clientInterface, tokenInterface, keysInterface, conf.AccessTokenExp, conf.RefreshTokenExp)

	loginUC := core.NewLoginUseCase(userInterface, tokenInterface, hashInterface, conf.SessionExp)
	registerUC := core.NewRegisterUseCase(userInterface, tokenInterface, hashInterface, conf.SessionExp)
	userUC := core.NewUserUseCase(userInterface)
	jwksUC := core.NewJWKSUseCase(keysInterface)

	e := echo.New()

	http.SetupHandlers(e, userUC, loginUC, registerUC, oauthWorkflow, jwksUC)	

	e.Logger.Fatal(e.Start(":8080"))
}
