package core

import (
	"time"
)

type Identity struct {
	ID string
	UserID string
	Type string
	ExternalID string
	Issuer string
	CreatedAt time.Time
	Credentials []Credential
}

func NewIdentity(itype, externalID, issuer string) (*Identity, error) {
	return &Identity{
		Type: itype,
		ExternalID: externalID,
		Issuer: issuer,
	}, nil
}
