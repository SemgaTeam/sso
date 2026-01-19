package entities

import (
	"github.com/google/uuid"

	"time"
)

type Session struct {
	ID uuid.UUID `gorm:"primaryKey"`
	UserID uuid.UUID
	User User
	CreatedAt time.Time
	ExpiresAt time.Time
	IP string
	UserAgent string 
	RevokedAt time.Time
}
