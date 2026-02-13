package infrastructure

import (
	"sso/internal/core"
	e "sso/internal/core/errors"

	"crypto/rand"
	"crypto/rsa"
)

type KeyInterface struct {
	keys []core.PrivateKey
}

func NewKeyInterface() *KeyInterface {
	return &KeyInterface{
		keys: []core.PrivateKey{},
	}
}

func (i *KeyInterface) GetPrivateKeys() ([]core.PrivateKey, error) {
	return i.keys, nil
}

func (i *KeyInterface) SavePrivateKey(key *core.PrivateKey) error {
	if key == nil {
		return e.KeyIsNil
	}

	i.keys = append(i.keys, *key)

	return nil
}

func (i *KeyInterface) Generate(name string) (*core.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, e.Unknown(err)
	}

	privateKey := core.PrivateKey{
		Value: *key,
		Name: name,
	}

	return &privateKey, nil
}
