package service

import (
	"github.com/SemgaTeam/sso/internal/repository"
	"github.com/SemgaTeam/sso/internal/config"
	"github.com/SemgaTeam/sso/internal/entities"
	e "github.com/SemgaTeam/sso/internal/error"
)

type Service interface {
	Register(RegisterInput) (*entities.User, error)
}

type service struct {
	conf *config.Config
	userRepo repository.UserRepository
	hashRepo repository.HashRepository
}

func NewService(userRepo repository.UserRepository, hashRepo repository.HashRepository) Service {
	return &service{
		conf: config.GetConfig(),
		userRepo: userRepo,
		hashRepo: hashRepo,
	}
}

type RegisterInput struct {
	Name string        // \
	Email string       // |- local password authentication
	Password string    // /

	Provider string    // email or oauth

	ExternalID string  // \
	Token string       // |- oauth2 authentication
	Issuer string      // /
}

// register only by email by now
func (s *service) Register(input RegisterInput) (*entities.User, error) {
	if input.Provider != "email" {
		panic("only email registration supported")
	}

	_, err := s.userRepo.ByEmail(input.Email)

	if err != nil {
		if err != e.UserNotFound {
			return nil, err
		}
	}	else {
		return nil, e.UserAlreadyExists
	}

	hash, err := s.hashRepo.HashPassword(input.Password)
	if err != nil {
		return nil, err
	}

	user := &entities.User {
		Name: input.Name,
		Email: input.Email,
		Status: "active",
	}

	identity := &entities.Identity{
		Type: input.Provider,
		ExternalID: input.ExternalID,
		Issuer: input.Issuer,
	}	

	credential := &entities.Credential {
		Type: "password",
		SecretHash: hash,
		Status: "active",
	}

	if err := s.userRepo.RegisterUser(user, identity, credential); err != nil {
		return nil, err
	}

	return user, nil
}
