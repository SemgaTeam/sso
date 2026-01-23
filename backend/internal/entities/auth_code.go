package entities

import (
	"github.com/google/uuid"
)

type AuthCode struct {
	UserID uuid.UUID
	ClientID uuid.UUID
	RedirectURI string
	Scope string
	TTL uint
}
