package usecase

import (
	"github.com/SemgaTeam/sso/internal/domain"
	"github.com/SemgaTeam/sso/internal/entities"
	e "github.com/SemgaTeam/sso/internal/error"
)

type RegisterUseCase struct {
	user domain.UserRepository
	hash domain.HashRepository
}

func NewRegisterUseCase(userRepo domain.UserRepository, hashRepo domain.HashRepository) *RegisterUseCase {
	return &RegisterUseCase{
		user: userRepo,
		hash: hashRepo,
	}
}

// register only by email by now
func (uc *RegisterUseCase) Execute(input domain.RegisterInput) (*entities.User, error) {
	if input.Provider != "email" {
		panic("only email registration supported")
	}

	_, err := uc.user.ByEmail(input.Email)

	switch err {
	case e.UserNotFound:
		break
	case nil:
		return nil, e.UserAlreadyExists
	default:
		return nil, err
	}

	hash, err := uc.hash.HashPassword(input.Password)
	if err != nil {
		return nil, err
	}

	user, err := domain.NewUser(input.Name, input.Email)
	if err != nil {
		return nil, err
	}

	identity, err := domain.NewIdentity(user.ID, input.Provider, input.ExternalID, input.Issuer)
	if err != nil {
		return nil, err
	}

	credential, err := domain.NewCredential(identity.ID, "password", hash)
	if err != nil {
		return nil, err
	}

	if err := uc.user.Save(user); err != nil {
		return nil, err
	}

	if err := uc.user.AddIdentity(identity); err != nil {
		return nil, err
	}

	if err := uc.user.AddCredential(credential); err != nil {
		return nil, err
	}

	return user, nil
}
