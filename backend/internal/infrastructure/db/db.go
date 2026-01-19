package db

import (
	"github.com/SemgaTeam/sso/internal/config"
	"gorm.io/gorm"
	"gorm.io/driver/postgres"
	"github.com/pressly/goose/v3"
	_ "github.com/jackc/pgx/v5/stdlib"

	"database/sql"
	"fmt"
)

func NewPostgresConnection(conf *config.Config) (*gorm.DB, error) {
	dsn := postgresDSN(conf.Postgres)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{TranslateError: true})	
	if err != nil {
		return nil, err
	}

	if conf.App.Debug {
		db = db.Debug()
	}

	return db, nil
}

func RunMigrations(conf *config.Postgres) error {
	dsn := postgresDSN(conf)
	sqlDb, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer sqlDb.Close()

	if err := goose.Up(sqlDb, conf.MigrationsPath); err != nil {
		return err
	}

	return nil
}

func postgresDSN(conf *config.Postgres) string {
	return fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s",
		conf.Host,
		conf.User,
		conf.Password, 
		conf.Db, 
		conf.Port,
		conf.SSLMode,
	)
}
