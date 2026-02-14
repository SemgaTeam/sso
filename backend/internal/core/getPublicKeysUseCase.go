package core

import (
	"go.uber.org/zap"

	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"context"
)

type GetPublicKeysUseCase struct {
	keys IPrivateKeys
}

func NewJWKSUseCase(keys IPrivateKeys) *GetPublicKeysUseCase {
	return &GetPublicKeysUseCase{
		keys,
	}
}

func (uc *GetPublicKeysUseCase) Execute(ctx context.Context) (JWKS, error) {
	log := getLoggerFromContext(ctx)

	privateKeys, err := uc.keys.GetPrivateKeys()
	if err != nil {
		log.Fatal("failed to get private keys", zap.Error(err))
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
