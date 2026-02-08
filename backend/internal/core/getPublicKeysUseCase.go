package core

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
)

type GetPublicKeysUseCase struct {
	keys IPrivateKeys
}

func (uc *GetPublicKeysUseCase) Execute() (JWKS, error) {
	privateKeys, err := uc.keys.GetPrivateKeys()
	if err != nil {
		return JWKS{}, err
	}

	var jwks JWKS
	var publicKeys []rsa.PublicKey
	for _, key := range privateKeys {
		publicKeys = append(publicKeys, key.Value.PublicKey)
		nStr := base64.RawURLEncoding.EncodeToString(key.Value.N.Bytes())
		eStr := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.Value.E)).Bytes())

		jwk := JWK{
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			N: nStr,
			E: eStr,
		}

		jwks.Keys = append(jwks.Keys, jwk)
	}

	return jwks, nil
}
