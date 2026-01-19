package domain

import (
	"github.com/SemgaTeam/sso/internal/entities"
	e "github.com/SemgaTeam/sso/internal/error"
	"github.com/google/uuid"
)

func NewUser(name, email string) (*entities.User, error) {
	return &entities.User{
		Name: name,
		Email: email,
		Status: "active",
	}, nil
}

func NewIdentity(userID uuid.UUID, itype, external_id, issuer string) (*entities.Identity, error) {
	return &entities.Identity{
		UserID: userID,
		Type: itype,
		ExternalID: external_id,
		Issuer: issuer,
	}, nil
}

func NewCredential(identityID uuid.UUID, itype, hash string) (*entities.Credential, error) {
	if hash == "" {
		return nil, e.EmptyPasswordIsNotPermitted
	}

	return &entities.Credential{
		IdentityID: identityID,
		Type: itype,
		SecretHash: hash,
		Status: "active",
	}, nil
}
