package test

import (
	"context"
	"sso/internal/core"
	"sso/internal/infrastructure"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestRegisterByEmailSuccess(t *testing.T) {
	userRepo := &FakeUserRepository{
		users: []core.User{},
	}

	tokenRepo := infrastructure.NewTokenInterface("secret", jwt.SigningMethodHS256)
	hashRepo := &FakeHashRepository{}

	sessionExp := 3600

	registerUC := core.NewRegisterUseCase(userRepo, tokenRepo, hashRepo, sessionExp)

	ctx := context.Background()
	input := core.RegisterInput{
		Provider: "email",

		Name: "user",
		Email: "user@example.com",
		Password: "password",
	}

	ssoSessionToken, err := registerUC.Execute(ctx, input)

	require.NoError(t, err)
	require.NotEmpty(t, ssoSessionToken)

	require.Len(t, userRepo.users, 1)
	require.Len(t, userRepo.identities, 1)
	require.Len(t, userRepo.credentials, 1)
}
