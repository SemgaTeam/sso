package entities

import (
	"github.com/google/uuid"

	"time"
)

type Client struct {
	ID uuid.UUID `gorm:"primaryKey"`
	Name string
	ClientID string
	ClientSecret string
	IsConfidential bool
	RedirectURIs []string
	Status string
	CreatedAt time.Time
}
