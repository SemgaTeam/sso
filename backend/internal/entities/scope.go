package entities

import (
	"github.com/google/uuid"
)

type Scope struct {
	ID uuid.UUID `gorm:"primaryKey"`
	Name string
	Description string
}
