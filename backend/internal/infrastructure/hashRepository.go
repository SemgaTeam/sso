package infrastructure

import (
	"github.com/SemgaTeam/sso/internal/config"
	e "github.com/SemgaTeam/sso/internal/error"
	"golang.org/x/crypto/bcrypt"
)

type HashRepository interface {
	HashPassword(string) (string, error)
	PasswordValid(string, string) bool
}

type hashRepository struct {
	conf *config.Hash
}

func NewHashRepository(conf *config.Hash) HashRepository {
	return &hashRepository{
		conf: conf,
	}
}

func (r *hashRepository) HashPassword(raw string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(raw), r.conf.Cost)
	if err != nil {
		return "", e.Unknown(err)
	}

	return string(bytes), nil
}

func (r *hashRepository) PasswordValid(raw, hashed string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(raw))
	return err == nil
}
