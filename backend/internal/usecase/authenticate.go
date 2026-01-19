package usecase

import (
	"github.com/SemgaTeam/sso/internal/domain"
	e "github.com/SemgaTeam/sso/internal/error"
	"github.com/SemgaTeam/sso/internal/entities"
)

type AuthenticateUserUseCase struct {
	user domain.UserRepository
	hash domain.HashRepository
}

func NewAuthenticateUserUseCase(userRepo domain.UserRepository, hashRepo domain.HashRepository) *AuthenticateUserUseCase {
	return &AuthenticateUserUseCase{
		user: userRepo,
		hash: hashRepo,
	}
}

func (uc *AuthenticateUserUseCase) Execute(input domain.AuthenticateInput) (*entities.User, error) {
	if input.Provider != "email" {
		panic("only email authentication supported")
	}

	user, err := uc.user.ByEmail(input.Email)
	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, e.UserNotFound
	}

	identity := getIdentityByType(user.Identities, "email")

	if identity == nil {
		return nil, e.IdentityNotExists
	}

	cred := getCredentialByType(identity.Credentials, "password")

	if cred == nil {
		return nil, e.CredentialNotExists
	}

	if !uc.hash.PasswordValid(input.Password, cred.SecretHash) {
		return nil, e.InvalidCredentials
	}

	return user, nil
}

func getIdentityByType(identities []entities.Identity, itype string) *entities.Identity {
	var res *entities.Identity

	for _, identity := range identities {
		if identity.Type == itype {
			res = &identity
		}
	}

	return res
}

func getCredentialByType(creds []entities.Credential, itype string) *entities.Credential {
	var res *entities.Credential

	for _, cred := range creds {
		if cred.Type == itype {
			res = &cred
		}
	}

	return res
}
