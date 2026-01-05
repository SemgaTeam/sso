package entities

import (
	"github.com/google/uuid"
)

type ClientScope struct {
	ClientID uuid.UUID
	Client Client
	ScopeID uuid.UUID
	Scope Scope
}
