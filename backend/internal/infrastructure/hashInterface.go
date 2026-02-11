package infrastructure

import (
	e "sso/internal/core/errors"
	"golang.org/x/crypto/bcrypt"
)

type HashInterface struct {
	hashCost int 
}

func NewHashInterface(hashCost int) *HashInterface {
	return &HashInterface{
		hashCost,
	}
}

func (i *HashInterface) HashPassword(raw string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(raw), i.hashCost)	
	if err != nil {
		return "", e.Unknown(err)
	}

	return string(hashedPassword), err
}

func (i *HashInterface) CheckPassword(raw, hash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(raw))		
	if err != nil {
		return e.Unknown(err)
	}

	return nil
}
