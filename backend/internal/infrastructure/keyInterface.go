package infrastructure

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"sso/internal/core"
)

type KeyInterface struct {
	keys []core.PrivateKey
}

func NewKeyInterface() *KeyInterface {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil
	}
	
	return &KeyInterface{
		keys: []core.PrivateKey{
			{
				Value: *privateKey,
				Name: "test_private_key",
			},
		},
	}
}

func (i *KeyInterface) GetPrivateKeys() ([]core.PrivateKey, error) {
	return i.keys, nil
}

func (i *KeyInterface) SavePrivateKey(key *core.PrivateKey) error {
	if key == nil {
		return errors.New("key is nil")
	}

	i.keys = append(i.keys, *key)

	return nil
}

func (i *KeyInterface) Generate(name string) (*core.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	privateKey := core.PrivateKey{
		Value: *key,
		Name: name,
	}

	return &privateKey, nil
}
