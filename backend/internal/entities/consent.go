package entities

import (
	"github.com/google/uuid"

	"time"
)

type Consent struct {
	UserID uuid.UUID
	User User
	ClientID uuid.UUID
	Client Client
	Scopes []string
	CreatedAt time.Time
}
