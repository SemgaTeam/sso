package entities

import (
	"github.com/google/uuid"
	"gorm.io/datatypes"

	"time"
)

type Identity struct {
	ID uuid.UUID
	UserID uuid.UUID
	Type string
	ExternalID string
	Issuer string
	Attributes datatypes.JSON
	CreatedAt time.Time
}
