package infrastructure

import (
	"sso/internal/core"
	"github.com/golang-jwt/jwt/v5"
)

type TokenInterface struct {
	signingKey string
	signingMethod jwt.SigningMethod
}

func NewTokenInterface(signingKey string, signingMethod jwt.SigningMethod) *TokenInterface {
	return &TokenInterface{
		signingKey,
		signingMethod,
	}
}

func (i *TokenInterface) Generate(claims *core.Claims) (string, error) {
	token := jwt.NewWithClaims(i.signingMethod, claims)
	signedStr, err := token.SignedString([]byte(i.signingKey)) 
	if err != nil {
		return "", err
	}

	return signedStr, nil
}
