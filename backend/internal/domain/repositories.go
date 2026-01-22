package domain

import (
	"github.com/SemgaTeam/sso/internal/entities"
	"github.com/google/uuid"
)

type UserRepository interface {
	Save(user *entities.User) error
	AddIdentity(identity *entities.Identity) error
	AddCredential(credential *entities.Credential) error

	ByID(id uuid.UUID) (*entities.User, error)
	ByEmail(email string) (*entities.User, error)
	ByIdentity(itype, external_id, issuer string) (*entities.User, error)
}

type HashRepository interface {
	HashPassword(raw string) (string, error)
	PasswordValid(raw string, hashed string) bool
}

type ConsentRepository interface {
	Save(userID, clientID uuid.UUID, scopes []string) error
	HasConsent(userID, clientID uuid.UUID, scopes []string) bool
	ClientScopes(clientID uuid.UUID) ([]string, error)
}

type ClientRepository interface {
	ByID(id uuid.UUID) (*entities.Client, error)
}

type AuthCodeRepository interface {
	Issue(user_id, client_id uuid.UUID, redirect_uri, scope string, ttl uint) (string, error)
	Get(code string) (user_id, client_id uuid.UUID, redirect_uri, scope string, err error) 
	Delete(code string) error
}
