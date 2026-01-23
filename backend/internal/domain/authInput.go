package domain

import (
	"github.com/google/uuid"
)

type AuthInput struct {
	ClientID uuid.UUID
	Scopes []string
	RedirectURI string

	AuthCode string

	Name string
	Email string
	Password string

	Provider string

	ExternalID string
	Token string
	Issuer string
}
