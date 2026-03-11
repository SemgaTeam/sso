package core

import (
	"sso/internal/core/entities"
	i "sso/internal/core/interfaces"

	"go.uber.org/zap"

	"context"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
)

type GetPublicKeysUseCase struct {
	keys i.IPrivateKeys
}

func NewJWKSUseCase(keys i.IPrivateKeys) *GetPublicKeysUseCase {
	return &GetPublicKeysUseCase{
		keys,
	}
}

func (uc *GetPublicKeysUseCase) Execute(ctx context.Context) (entities.JWKS, error) {
	log := getLoggerFromContext(ctx)

	privateKeys, err := uc.keys.GetPrivateKeys()
	if err != nil {
		log.Fatal("failed to get private keys", zap.Error(err))
		return entities.JWKS{}, err
	}

	var jwks entities.JWKS
	var publicKeys []rsa.PublicKey
	for _, key := range privateKeys {
		publicKeys = append(publicKeys, key.Value.PublicKey)
		nStr := base64.RawURLEncoding.EncodeToString(key.Value.N.Bytes())
		eStr := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.Value.E)).Bytes())

		jwk := entities.JWK{
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			N:   nStr,
			E:   eStr,
		}

		jwks.Keys = append(jwks.Keys, jwk)
	}

	return jwks, nil
}
