package test

import (
	"sso/internal/core"
	"sso/internal/infrastructure"
	"time"

	"context"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestLoginByEmailSuccess(t *testing.T) {
	userRepo := &FakeUserRepository{
		users: []core.User{
			{
				ID: "user_id1",
				Name: "1",
				Email: "email@example.com",
				Status: "active",
				Identities: []core.Identity{
					{
						ID: "identity_id1",
						UserID: "1",
						Type: "email",
						ExternalID: "email@example.com",
						Issuer: "sso.test.com",
						CreatedAt: time.Now(),
						Credentials: []core.Credential{
							{
								ID: "credential_id1",
								IdentityID: "identity_id1",
								Type: "password",
								Hash: "password_hashed",
								Status: "active",
								CreatedAt: time.Now(),
							},
						},
					},
				},
			},
		},
	}

	tokenRepo := infrastructure.NewTokenInterface("secret", jwt.SigningMethodHS256)
	hashRepo := &FakeHashRepository{}

	loginUC := core.NewLoginUseCase(userRepo, tokenRepo, hashRepo)

	ctx := context.Background()

	input := core.LoginInput{
		Provider: "email",

		Email: "email@example.com",
		Password: "password",
	}

	ssoSessionToken, err := loginUC.Execute(ctx, input)

	require.NoError(t, err)
	require.NotEmpty(t, ssoSessionToken)
}
