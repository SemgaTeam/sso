package main

import (
	"github.com/SemgaTeam/sso/internal/infrastructure/db"
	"github.com/SemgaTeam/sso/internal/config"

	"fmt"
)

func main() {
	conf := config.GetConfig()

	if err := db.RunMigrations(conf.Postgres); err != nil {
		panic(err)
	}

	fmt.Println("Hello world")
}
