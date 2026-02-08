package core

import (
	"crypto/rsa"
)

type GetPublicKeysUseCase struct {
	keys IPrivateKeys
}

func (uc *GetPublicKeysUseCase) Execute() ([]rsa.PublicKey, error) {
	privateKeys, err := uc.keys.GetPrivateKeys()
	if err != nil {
		return nil, err
	}

	var publicKeys []rsa.PublicKey
	for _, key := range privateKeys {
		publicKeys = append(publicKeys, key.Value.PublicKey)
	}

	return publicKeys, nil
}
