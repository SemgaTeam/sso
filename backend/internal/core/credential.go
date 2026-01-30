package core

import "time"

type Credential struct {
	ID string
	IdentityID string
	Type string
	Hash string
	Status string
	CreatedAt time.Time
}

func NewCredential(ctype string, hash string) (*Credential, error) {
	return &Credential{
		Type: ctype,
		Hash: hash,
	}, nil
}
