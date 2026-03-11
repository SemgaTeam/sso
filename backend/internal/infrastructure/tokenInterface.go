package infrastructure

import (
	"sso/internal/core/entities"
	e "sso/internal/core/errors"

	"github.com/golang-jwt/jwt/v5"
)

type TokenInterface struct {
	signingKey    string
	signingMethod jwt.SigningMethod
}

func NewTokenInterface(signingKey string, signingMethod jwt.SigningMethod) *TokenInterface {
	return &TokenInterface{
		signingKey,
		signingMethod,
	}
}

func (i *TokenInterface) Generate(claims *entities.Claims) (string, error) {
	token := jwt.NewWithClaims(i.signingMethod, claims)
	signedStr, err := token.SignedString([]byte(i.signingKey))
	if err != nil {
		return "", e.Unknown(err)
	}

	return signedStr, nil
}

func (i *TokenInterface) SignWithKey(claims *entities.Claims, key entities.PrivateKey) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	signed, err := token.SignedString(&key.Value)
	if err != nil {
		return "", e.Unknown(err)
	}

	return signed, nil
}
