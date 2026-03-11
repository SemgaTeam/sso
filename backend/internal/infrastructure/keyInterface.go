package infrastructure

import (
	"sso/internal/core/entities"
	e "sso/internal/core/errors"

	"crypto/rand"
	"crypto/rsa"
)

type KeyInterface struct {
	keys []entities.PrivateKey
}

func NewKeyInterface() *KeyInterface {
	return &KeyInterface{
		keys: []entities.PrivateKey{},
	}
}

func (i *KeyInterface) GetPrivateKeys() ([]entities.PrivateKey, error) {
	return i.keys, nil
}

func (i *KeyInterface) SavePrivateKey(key *entities.PrivateKey) error {
	if key == nil {
		return e.KeyIsNil
	}

	i.keys = append(i.keys, *key)

	return nil
}

func (i *KeyInterface) Generate(name string) (*entities.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, e.Unknown(err)
	}

	privateKey := entities.PrivateKey{
		Value: *key,
		Name:  name,
	}

	return &privateKey, nil
}
