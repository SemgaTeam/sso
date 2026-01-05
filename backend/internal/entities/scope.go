package entities

import (
	"github.com/google/uuid"
)

type Scope struct {
	ID uuid.UUID
	Name string
	Description string
}
