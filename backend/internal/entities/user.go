package entities

import (
	"github.com/google/uuid"

	"time"
)

type User struct {
	ID uuid.UUID
	Name string
	Email string
	Status string
	CreatedAt time.Time
}
