package domain

import (
	"github.com/SemgaTeam/sso/internal/entities"
	"github.com/google/uuid"

	"time"
)

func NewToken(userID, clientID uuid.UUID, expiresAt time.Time) (*entities.Token, error) {
	return &entities.Token{
		SubjectUserID: userID,
		ClientID: clientID,
		ExpiresAt: expiresAt,
	}, nil
}
