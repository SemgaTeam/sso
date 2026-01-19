package usecase

import (
	"github.com/SemgaTeam/sso/mock"

	e "github.com/SemgaTeam/sso/internal/error"
	"github.com/SemgaTeam/sso/internal/entities"
	"github.com/SemgaTeam/sso/internal/domain"
	"github.com/golang/mock/gomock"

	"testing"
	"errors"
)

func TestAuthenticate(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock.NewMockUserRepository(ctrl)
	mockHashRepo := mock.NewMockHashRepository(ctrl)

	authUC := NewAuthenticateUserUseCase(mockUserRepo, mockHashRepo)	

	tests := []struct{
		testName string
		input domain.AuthenticateInput
		wantError bool
		wantedError error
		wantPanic bool
		setupMock func()
	}{
		{
			testName: "success case (email)",
			input: domain.AuthenticateInput{
				Email: "user@example.com",
				Password: "password",
				Provider: "email",
			},
			wantError: false,
			setupMock: func(){
				passwordCred := entities.Credential{
					SecretHash: "hashed password",
					Type: "password",
				}

				passwordId := entities.Identity{
					Type: "email",
					Credentials: []entities.Credential{
						passwordCred,
					},
				}

				user := entities.User{
					Identities: []entities.Identity{
						passwordId,
					},
				}

				mockUserRepo.
					EXPECT().
					ByEmail(gomock.Eq("user@example.com")).
					Return(&user, nil)

				mockHashRepo.
					EXPECT().
					PasswordValid(gomock.Eq("password"), gomock.Eq("hashed password")).
					Return(true)	
			},
		},
		{
			testName: "empty password (email)",
			input: domain.AuthenticateInput{
				Email: "user@example.com",
				Password: "",
				Provider: "email",
			},
			wantError: true,
			wantedError: e.InvalidCredentials,
			setupMock: func(){
				passwordCred := entities.Credential{
					SecretHash: "hashed password",
					Type: "password",
				}

				passwordId := entities.Identity{
					Type: "email",
					Credentials: []entities.Credential{
						passwordCred,
					},
				}

				user := entities.User{
					Identities: []entities.Identity{
						passwordId,
					},
				}

				mockUserRepo.
					EXPECT().
					ByEmail(gomock.Eq("user@example.com")).
					Return(&user, nil)

				mockHashRepo.
					EXPECT().
					PasswordValid(gomock.Eq(""), gomock.Eq("hashed password")).
					Return(false)	
			},
		},
		{
			testName: "invalid password (email)",
			input: domain.AuthenticateInput{
				Email: "user@example.com",
				Password: "password",
				Provider: "email",
			},
			wantError: true,
			wantedError: e.InvalidCredentials,
			setupMock: func(){
				passwordCred := entities.Credential{
					SecretHash: "hashed password",
					Type: "password",
				}

				passwordId := entities.Identity{
					Type: "email",
					Credentials: []entities.Credential{
						passwordCred,
					},
				}

				user := entities.User{
					Identities: []entities.Identity{
						passwordId,
					},
				}

				mockUserRepo.
					EXPECT().
					ByEmail(gomock.Eq("user@example.com")).
					Return(&user, nil)

				mockHashRepo.
					EXPECT().
					PasswordValid(gomock.Eq("password"), gomock.Eq("hashed password")).
					Return(false)	
			},
		},
		{
			testName: "user not found (email)",
			input: domain.AuthenticateInput{
				Email: "user@example.com",
				Password: "password",
				Provider: "email",
			},
			wantError: true,
			wantedError: e.UserNotFound,
			setupMock: func(){
				mockUserRepo.
					EXPECT().
					ByEmail(gomock.Eq("user@example.com")).
					Return(nil, nil)
			},
		},
		{
			testName: "no password identity (email)",
			input: domain.AuthenticateInput{
				Email: "user@example.com",
				Password: "password",
				Provider: "email",
			},
			wantError: true,
			wantedError: e.IdentityNotExists,
			setupMock: func(){
				oauthId := entities.Identity{
					Type: "oauth",
					Credentials: []entities.Credential{
						// ...
					},
				}

				user := entities.User{
					Identities: []entities.Identity{
						oauthId,
					},
				}

				mockUserRepo.
					EXPECT().
					ByEmail(gomock.Eq("user@example.com")).
					Return(&user, nil)
			},
		},
		{
			testName: "no password credential (email)",
			input: domain.AuthenticateInput{
				Email: "user@example.com",
				Password: "password",
				Provider: "email",
			},
			wantError: true,
			wantedError: e.CredentialNotExists,
			setupMock: func(){
				passwordId := entities.Identity{
					Type: "email",
					Credentials: []entities.Credential{
					},
				}

				user := entities.User{
					Identities: []entities.Identity{
						passwordId,
					},
				}

				mockUserRepo.
					EXPECT().
					ByEmail(gomock.Eq("user@example.com")).
					Return(&user, nil)
			},
		},
		{
			testName: "ByEmail unknown error (email)",
			input: domain.AuthenticateInput{
				Email: "user@example.com",
				Password: "password",
				Provider: "email",
			},
			wantError: true,
			setupMock: func(){
				mockUserRepo.
					EXPECT().
					ByEmail(gomock.Eq("user@example.com")).
					Return(nil, errors.New("unknown")) 
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			tt.setupMock()

			defer func(){
				if r := recover(); (r != nil) != tt.wantPanic {
					t.Errorf("AuthenticateUserUC panic (%v) != wantPanic (%v)", r != nil, tt.wantPanic)	
				}
			}()

			_, err := authUC.Execute(tt.input)

			if (err != nil) != tt.wantError {
				t.Errorf("AuthenticateUserUC error (%v) != wantedError (%v)", err, tt.wantedError)
			}

			if err != tt.wantedError && tt.wantedError != nil {
				t.Errorf("AuthenticateUserUC error (%v) != wantedError (%v)", err, tt.wantedError)
			}
		}) 
	}
}
