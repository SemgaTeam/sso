package main

import (
	"sso/internal/config"
	"sso/internal/core"
	"sso/internal/infrastructure"
	"sso/internal/infrastructure/http"
	"sso/internal/log"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/labstack/echo/v4"
	"github.com/pressly/goose/v3"
	"go.uber.org/zap"

	"context"
	"database/sql"
	"os"
)

func main() {
	log.InitLogger("logs/main.log")

	conf, err := config.GetConfig()
	if err != nil {
		log.Log.Fatal("failed to init config", zap.Error(err))
		os.Exit(1)
	}

	ctx := context.Background()

	sqlDb, err := sql.Open("pgx", conf.PostgresURL)
	if err != nil {
		log.Log.Fatal("failed to run migrations", zap.Error(err))
		os.Exit(1)
	}

	if err := goose.Up(sqlDb, conf.MigrationsPath); err != nil {
		log.Log.Fatal("failed to run migrations", zap.Error(err), zap.String("migrations_path", conf.MigrationsPath))
		os.Exit(1)
	}
	sqlDb.Close()

	pool, err := pgxpool.New(ctx, conf.PostgresURL)
	if err != nil {
		log.Log.Fatal("failed to open postgresql", zap.Error(err), zap.String("url", conf.PostgresURL))
		os.Exit(1)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		log.Log.Fatal("ping db error", zap.Error(err))
		os.Exit(1)
	}

	log.Log.Info("Connected to postgres")
	
	clientInterface := infrastructure.NewClientInterface(pool)
	tokenInterface := infrastructure.NewTokenInterface(conf.SigningKey, conf.SigningMethod)
	userInterface := infrastructure.NewUserInterface(pool)
	hashInterface := infrastructure.NewHashInterface(conf.HashCost)
	keysInterface := infrastructure.NewKeyInterface()

	log.Log.Info("Initialized interfaces")

	privateKey, err := keysInterface.Generate("test_key")
	if err != nil {
		log.Log.Fatal("error generating private key", zap.Error(err))
		os.Exit(1)
	}
	keysInterface.SavePrivateKey(privateKey)

	oauthWorkflow := core.NewOAuthWorkflow(clientInterface, tokenInterface, keysInterface, conf.AccessTokenExp, conf.RefreshTokenExp)

	loginUC := core.NewLoginUseCase(userInterface, tokenInterface, hashInterface, conf.SessionExp)
	registerUC := core.NewRegisterUseCase(userInterface, tokenInterface, hashInterface, conf.SessionExp)
	userUC := core.NewUserUseCase(userInterface)
	jwksUC := core.NewJWKSUseCase(keysInterface)

	log.Log.Info("Initialized use cases")

	e := echo.New()

	http.SetupHandlers(e, log.Log, userUC, loginUC, registerUC, oauthWorkflow, jwksUC)	

	log.Log.Info("HTTP handlers setup")

	log.Log.Fatal("Server error", zap.Error(e.Start(":8080")))
}
