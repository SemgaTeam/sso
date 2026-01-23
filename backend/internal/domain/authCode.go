package domain

import (
	"github.com/SemgaTeam/sso/internal/entities"
	"github.com/google/uuid"
)

func NewAuthCode(userID, clientID uuid.UUID, redirectURI, scope string, ttl uint) (*entities.AuthCode, error) {
	return &entities.AuthCode{
		UserID: userID,
		ClientID: clientID,
		RedirectURI: redirectURI,
		Scope: scope,
		TTL: ttl,
	}, nil
}
