package entities

import (
	"github.com/google/uuid"
	"gorm.io/datatypes"

	"time"
)

type AuditEvent struct {
	ID uuid.UUID
	Type string
	UserID uuid.UUID
	User User
	ClientID uuid.UUID
	Client Client
	IP string
	CreatedAt time.Time
	Metadata datatypes.JSON
}
