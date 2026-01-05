package entities

import (
	"github.com/google/uuid"

	"time"
)

type Credential struct {
	ID uuid.UUID
	IdentityID uuid.UUID
	Identity Identity
	Type string
	SecretHash string
	CreatedAt time.Time
	LastUsedAt time.Time
	ExpiresAt time.Time
	Status string
}
