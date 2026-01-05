package entities

import (
	"github.com/google/uuid"

	"time"
)

type Token struct {
	ID uuid.UUID
	SubjectUserID uuid.UUID
	User User `gorm:"foreignKey:SubjectUserID"`
	ClientID uuid.UUID
	Client Client
	Token string
	CreatedAt time.Time
	ExpiresAt time.Time
	IsRevoked bool
}
