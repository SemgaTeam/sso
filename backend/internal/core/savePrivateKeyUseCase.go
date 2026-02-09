package core

import "crypto/rsa"

type SavePrivateKeyUseCase struct {
	keys IPrivateKeys
}

type PrivateKey struct {
	Value rsa.PrivateKey
	Name string
}

func (uc *SavePrivateKeyUseCase) Execute(value rsa.PrivateKey, name string) error {
	key := PrivateKey{
		Value: value,
		Name: name,
	}

	return uc.keys.SavePrivateKey(&key)
}
