package core

import (
	"github.com/golang-jwt/jwt/v5"

	"time"
)

type Claims struct {
	ClientID string `json:"client_id,omitempty"`
	jwt.RegisteredClaims
}

func NewClaims(clientID, userID string, expiration int) (*Claims, error) {
	expiresAt := jwt.NewNumericDate(
		time.Now().Add(
			time.Duration(expiration)*time.Second,
		),
	)

	return &Claims{
		ClientID: clientID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: userID,
			ExpiresAt: expiresAt,
		},
	}, nil
}
