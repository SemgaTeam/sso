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
}

func NewIdentity(userID, itype, externalID, issuer string) (*Identity, error) {
	return &Identity{
		UserID: userID,
		Type: itype,
		ExternalID: externalID,
		Issuer: issuer,
	}, nil
}
