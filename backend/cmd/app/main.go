package main

import (
	"github.com/SemgaTeam/sso/internal/db"
	"github.com/SemgaTeam/sso/internal/config"

	"fmt"
)

func main() {
	conf := config.GetConfig()
	migrationPath := "migrations"
	if err := db.RunMigrations(conf.Postgres, migrationPath); err != nil {
		panic(err)
	}

	fmt.Println("Hello world")
}
