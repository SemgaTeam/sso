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

	registerUC := core.NewRegisterUseCase(userRepo, tokenRepo, hashRepo)

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

func TestRegisterOauthUserExists(t *testing.T) {
	userRepo := &FakeUserRepository{
		users: []core.User{
			{
				ID: "user_id",
				Name: "user",
				Email: "user@example.com",
				Status: "active",
			},
		},
		identities: []core.Identity{
			{
				ID: "identity_id",
				UserID: "user_id",
				Type: "oauth",
				ExternalID: "external_user_id",
				Issuer: "test.issuer.com",
			},
		},
	}

	tokenRepo := infrastructure.NewTokenInterface("secret", jwt.SigningMethodHS256)
	hashRepo := &FakeHashRepository{}

	registerUC := core.NewRegisterUseCase(userRepo, tokenRepo, hashRepo)

	token := map[string]string {
		"email": "user@example.com",
		"raw": "token",
	}

	ctx := context.Background()
	input := core.RegisterInput{
		Provider: "oauth",

		Token: token,
		Issuer: "test.issuer.com",
		ExternalID: "external_user_id",
	}

	ssoSessionToken, err := registerUC.Execute(ctx, input)

	require.NoError(t, err)
	require.NotEmpty(t, ssoSessionToken)

	require.Len(t, userRepo.users, 1)
	require.Len(t, userRepo.identities, 1)
}

func TestRegisterOauthUserExistsWithoutIdentity(t *testing.T) {
	userRepo := &FakeUserRepository{
		users: []core.User{
			{
				ID: "user_id",
				Name: "user",
				Email: "user@example.com",
				Status: "active",
			},
		},
	}

	tokenRepo := infrastructure.NewTokenInterface("secret", jwt.SigningMethodHS256)
	hashRepo := &FakeHashRepository{}

	registerUC := core.NewRegisterUseCase(userRepo, tokenRepo, hashRepo)

	token := map[string]string {
		"email": "user@example.com",
		"raw": "token",
	}

	ctx := context.Background()
	input := core.RegisterInput{
		Provider: "oauth",

		Token: token,
		Issuer: "test.issuer.com",
		ExternalID: "test_issuer_user_id",
	}

	ssoSessionToken, err := registerUC.Execute(ctx, input)

	require.NoError(t, err)
	require.NotEmpty(t, ssoSessionToken)

	require.Len(t, userRepo.users, 1)
	require.Len(t, userRepo.identities, 1)
	require.Len(t, userRepo.credentials, 1)

	user := userRepo.users[0]
	identity := userRepo.identities[0]
	credential := userRepo.credentials[0]

	require.Equal(t, input.Issuer, identity.Issuer)
	require.Equal(t, input.ExternalID, identity.ExternalID)
	require.Equal(t, user.ID, identity.UserID)
	require.Equal(t, input.Provider, identity.Type)

	require.Equal(t, identity.ID, credential.IdentityID)
	require.Equal(t, token["raw"], credential.Hash)
}

func TestRegisterOauthUserNotExistsWithEmailSuccess(t *testing.T) {
	userRepo := &FakeUserRepository{
		users: []core.User{},
	}

	tokenRepo := infrastructure.NewTokenInterface("secret", jwt.SigningMethodHS256)
	hashRepo := &FakeHashRepository{}

	registerUC := core.NewRegisterUseCase(userRepo, tokenRepo, hashRepo)

	token := map[string]string {
		"email": "user@example.com",
		"raw": "token",
	}

	ctx := context.Background()
	input := core.RegisterInput{
		Provider: "oauth",

		Token: token,
		Issuer: "test.issuer.com",
		ExternalID: "test_issuer_user_id",
	}

	ssoSessionToken, err := registerUC.Execute(ctx, input)

	require.NoError(t, err)
	require.NotEmpty(t, ssoSessionToken)

	require.Len(t, userRepo.users, 1)
	require.Len(t, userRepo.identities, 1)
	require.Len(t, userRepo.credentials, 1)

	user := userRepo.users[0]
	identity := userRepo.identities[0]
	credential := userRepo.credentials[0]

	require.Equal(t, input.Issuer, identity.Issuer)
	require.Equal(t, input.ExternalID, identity.ExternalID)
	require.Equal(t, user.ID, identity.UserID)
	require.Equal(t, input.Provider, identity.Type)

	require.Equal(t, identity.ID, credential.IdentityID)
	require.Equal(t, token["raw"], credential.Hash)
}
