package test

import (
	"sso/internal/core"
	"github.com/stretchr/testify/require"

	"context"
	"testing"
)

type googleInput struct {
	Email string
	RawToken string
	Provider string
	ExternalID string
	Issuer string
}

func TestGoogleOAuth(t *testing.T) {
	tests := []struct{
		testName string
		wantError bool
		input googleInput
		setupRepositories func() (*FakeUserRepository, *FakeHashRepository, *FakeTokenRepository)
		runChecks func(*testing.T, googleInput, *core.User, *FakeUserRepository, error)
	}{
		{
			testName: "user not exists with email, must create user, identity and credential",
			wantError: false,
			input: googleInput{
				Email: "user@example.com",
				RawToken: "token",
				Provider: "oauth",
				ExternalID: "test_issuer_user_id",
				Issuer: "test.issuer.com",
			},

			setupRepositories: func() (*FakeUserRepository, *FakeHashRepository, *FakeTokenRepository) {
				userRepo := &FakeUserRepository{
					users: []core.User{},
				}
				hashRepo := &FakeHashRepository{}
				tokenRepo := &FakeTokenRepository{}

				return userRepo, hashRepo, tokenRepo
			},

			runChecks: func(t *testing.T, input googleInput, user *core.User, userRepo *FakeUserRepository, err error) {
				require.NoError(t, err)
				require.NotNil(t, user)

				require.Len(t, userRepo.users, 1)
				require.Len(t, userRepo.identities, 1)
				require.Len(t, userRepo.credentials, 1)

				identity := userRepo.identities[0]
				credential := userRepo.credentials[0]

				require.Equal(t, input.Issuer, identity.Issuer)
				require.Equal(t, input.ExternalID, identity.ExternalID)
				require.Equal(t, user.ID, identity.UserID)
				require.Equal(t, input.Provider, identity.Type)

				require.Equal(t, identity.ID, credential.IdentityID)
				require.Equal(t, input.RawToken, credential.Hash)
			},
		},

		{
			testName: "user exists with email, but without identity, must create identity and credential",
			wantError: false,
			input: googleInput{
				Email: "user@example.com",
				RawToken: "token",
				Provider: "oauth",
				ExternalID: "test_issuer_user_id",
				Issuer: "test.issuer.com",
			},

			setupRepositories: func() (*FakeUserRepository, *FakeHashRepository, *FakeTokenRepository) {
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
				hashRepo := &FakeHashRepository{}
				tokenRepo := &FakeTokenRepository{}

				return userRepo, hashRepo, tokenRepo
			},

			runChecks: func(t *testing.T, input googleInput, user *core.User, userRepo *FakeUserRepository, err error) {
				require.NoError(t, err)
				require.NotNil(t, user)

				require.Len(t, userRepo.users, 1)
				require.Len(t, userRepo.identities, 1)
				require.Len(t, userRepo.credentials, 1)

				identity := userRepo.identities[0]
				credential := userRepo.credentials[0]

				require.Equal(t, input.Issuer, identity.Issuer)
				require.Equal(t, input.ExternalID, identity.ExternalID)
				require.Equal(t, user.ID, identity.UserID)
				require.Equal(t, input.Provider, identity.Type)

				require.Equal(t, identity.ID, credential.IdentityID)
				require.Equal(t, input.RawToken, credential.Hash)
			},
		},

		{
			testName: "user exists with identity",
			wantError: false,
			input: googleInput{
				Email: "user@example.com",
				RawToken: "token",
				Provider: "oauth",
				ExternalID: "external_user_id",
				Issuer: "test.issuer.com",
			},
			setupRepositories: func() (*FakeUserRepository, *FakeHashRepository, *FakeTokenRepository) {
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
				hashRepo := &FakeHashRepository{}
				tokenRepo := &FakeTokenRepository{}

				return userRepo, hashRepo, tokenRepo
			},
			runChecks: func(t *testing.T, input googleInput, user *core.User, userRepo *FakeUserRepository, err error) {
				require.NoError(t, err)
				require.NotNil(t, user)

				require.Len(t, userRepo.users, 1)
				require.Len(t, userRepo.identities, 1)
			},
		},
		// test template
		// {
		// 	testName: "",
		// 	wantError: false,
		// 	input: googleInput{
		// 		Email: "",
		// 		RawToken: "",
		// 		Provider: "",
		// 		ExternalID: "",
		// 		Issuer: "",
		// 	},
		// 	setupRepositories: func() (*FakeUserRepository, *FakeHashRepository, *FakeTokenRepository) {
		// 		userRepo := &FakeUserRepository{
		// 			users: []core.User{
		// 				{
		// 				},
		// 			},
		// 			identities: []core.Identity{
		// 				{
		// 				},
		// 			},
		// 		}
		// 		hashRepo := &FakeHashRepository{}
		// 		tokenRepo := &FakeTokenRepository{}

		// 		return userRepo, hashRepo, tokenRepo
		// 	},
		// 	runChecks: func(t *testing.T, input googleInput, user *core.User, userRepo *FakeUserRepository, err error) {
		// 	},
		// },
	}

	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			ctx := context.Background()
			userRepo, _, _ := tt.setupRepositories()
			user, err := core.GoogleOAuth(ctx, userRepo, tt.input.Email, tt.input.RawToken, tt.input.Provider, tt.input.ExternalID, tt.input.Issuer)

			tt.runChecks(t, tt.input, user, userRepo, err)
		})
	}
}
