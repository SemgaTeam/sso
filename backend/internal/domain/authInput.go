package domain

import (
	"github.com/google/uuid"
)

type authIntent string

const (
	IntentLogin    			 authIntent = "login"
	IntentRegister 			 authIntent = "register"
	IntentExchangeTokens authIntent = "exchange tokens"
)

type AuthInput struct {
	Intent authIntent	

	ClientID uuid.UUID
	Scopes []string
	RedirectURI string

	Name string
	Email string
	Password string

	Provider string

	ExternalID string
	Token string
	Issuer string
}
