package application

import (
	"github.com/SemgaTeam/sso/internal/domain"
	"github.com/SemgaTeam/sso/internal/entities"
)

type AuthenticateUC interface {
	Execute(input domain.AuthenticateInput) (*entities.User, error)
}

type RegisterUC interface {
	Execute(input domain.RegisterInput) (*entities.User, error)
}
