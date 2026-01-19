package entities

import (
	"github.com/google/uuid"
	"gorm.io/datatypes"

	"time"
)

type Identity struct {
	ID uuid.UUID `gorm:"primaryKey"`
	UserID uuid.UUID
	User User
	Type string
	ExternalID string
	Issuer string
	Attributes datatypes.JSON
	CreatedAt time.Time
	Credentials []Credential
}
