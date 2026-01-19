package config

import (
	"github.com/spf13/viper"

	"strings"
	"sync"
)

type (
	Config struct {
		App *App
		Postgres *Postgres
	}

	App struct {
		Address string
		Port string
		Debug bool
	}

	Postgres struct {
		User string
		Password string
		Db string
		Host string
		Port string
		SSLMode string
		MigrationsPath string `mapstructure:"migrationsPath"`
	}

	Hash struct {
		Cost int
	}
)

var (
	once sync.Once
	configInstance *Config
)

func GetConfig() *Config {
	once.Do(func () {
		viper.AddConfigPath("./")
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")

		viper.AutomaticEnv()
		viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

		viper.SetDefault("app.address", "")
		viper.SetDefault("app.port", "8080")
		viper.SetDefault("app.debug", "true")

		viper.SetDefault("postgres.user", "postgres")
		viper.SetDefault("postgres.db", "postgres")
		viper.SetDefault("postgres.port", "5432")
		viper.SetDefault("postgres.host", "db")
		viper.SetDefault("postgres.password", "")
		viper.SetDefault("postgres.sslmode", "disable")
		viper.SetDefault("postgres.migrationsPath", "migrations")

		viper.SetDefault("hash.cost", 10)

		if err := viper.ReadInConfig(); err != nil {
			if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
				panic(err)
			}
		}

		if err := viper.Unmarshal(&configInstance); err != nil {
			panic(err)
		}
	})

	return configInstance
}
