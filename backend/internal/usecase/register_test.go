package usecase

import(
	"github.com/SemgaTeam/sso/mock"
	e "github.com/SemgaTeam/sso/internal/error"
	"github.com/SemgaTeam/sso/internal/entities"
	"github.com/SemgaTeam/sso/internal/domain"
	"github.com/golang/mock/gomock"

	"testing"
	"errors"
)

func TestRegister(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock.NewMockUserRepository(ctrl)
	mockHashRepo := mock.NewMockHashRepository(ctrl)

	registerUC := NewRegisterUseCase(mockUserRepo, mockHashRepo)

	tests := []struct{
		testName string
		input domain.RegisterInput
		wantError bool
		wantedError error
		wantPanic bool
		setupMock func()
	}{
		{
			testName: "success case (email)",
			input: domain.RegisterInput{
				Name: "user",
				Email: "user@example.com",
				Password: "password",
				Provider: "email",
			},
			wantError: false,
			setupMock: func(){
				mockUserRepo.
					EXPECT().
					ByEmail(gomock.Eq("user@example.com")).
					Return(nil, e.UserNotFound)

				mockHashRepo.
					EXPECT().
					HashPassword(gomock.Eq("password")).
					Return("hashed password", nil)	

				mockUserRepo.
					EXPECT().
					Save(gomock.Any()).
					Return(nil)

				mockUserRepo.
					EXPECT().
					AddIdentity(gomock.Any()).
					Return(nil)

				mockUserRepo.
					EXPECT().
					AddCredential(gomock.Any()).
					Return(nil)
			},
		},
		{
			testName: "empty password (email)",
			input: domain.RegisterInput{
				Name: "user",
				Email: "user@example.com",
				Password: "",
				Provider: "email",
			},
			wantError: true,
			wantedError: e.EmptyPasswordIsNotPermitted,
			setupMock: func(){
				mockUserRepo.
					EXPECT().
					ByEmail(gomock.Eq("user@example.com")).
					Return(nil, e.UserNotFound)

				mockHashRepo.
					EXPECT().
					HashPassword(gomock.Eq("")).
					Return("", nil).
					AnyTimes()
			},
		},
		{
			testName: "user already exists (email)",
			input: domain.RegisterInput{
				Name: "user",
				Email: "user@example.com",
				Password: "password",
				Provider: "email",
			},
			wantError: true,
			wantedError: e.UserAlreadyExists,
			setupMock: func(){
				mockUserRepo.
					EXPECT().
					ByEmail(gomock.Eq("user@example.com")).
					Return(&entities.User{}, nil)
			},
		},
		{
			testName: "ByEmail unknown error (email)",
			input: domain.RegisterInput{
				Name: "user",
				Email: "user@example.com",
				Password: "password",
				Provider: "email",
			},
			wantError: true,
			setupMock: func(){
				mockUserRepo.
					EXPECT().
					ByEmail(gomock.Eq("user@example.com")).
					Return(nil, errors.New("unknown error"))
			},
		},
		{
			testName: "HashPassword unknown error (email)",
			input: domain.RegisterInput{
				Name: "user",
				Email: "user@example.com",
				Password: "password",
				Provider: "email",
			},
			wantError: true,
			setupMock: func(){
				mockUserRepo.
					EXPECT().
					ByEmail(gomock.Eq("user@example.com")).
					Return(nil, e.UserNotFound)

				mockHashRepo.
					EXPECT().
					HashPassword(gomock.Eq("password")).
					Return("", errors.New("unknown error"))	
			},
		},
		{
			testName: "Save user unknown error (email)",
			input: domain.RegisterInput{
				Name: "user",
				Email: "user@example.com",
				Password: "password",
				Provider: "email",
			},
			wantError: true,
			setupMock: func(){
				mockUserRepo.
					EXPECT().
					ByEmail(gomock.Eq("user@example.com")).
					Return(nil, e.UserNotFound)

				mockHashRepo.
					EXPECT().
					HashPassword(gomock.Eq("password")).
					Return("hashed password", nil)	

				mockUserRepo.
					EXPECT().
					Save(gomock.Any()).
					Return(errors.New("unknown"))
			},
		},
		{
			testName: "AddIdentity unknown error (email)",
			input: domain.RegisterInput{
				Name: "user",
				Email: "user@example.com",
				Password: "password",
				Provider: "email",
			},
			wantError: true,
			setupMock: func(){
				mockUserRepo.
					EXPECT().
					ByEmail(gomock.Eq("user@example.com")).
					Return(nil, e.UserNotFound)

				mockHashRepo.
					EXPECT().
					HashPassword(gomock.Eq("password")).
					Return("hashed password", nil)	

				mockUserRepo.
					EXPECT().
					Save(gomock.Any()).
					Return(nil)

				mockUserRepo.
					EXPECT().
					AddIdentity(gomock.Any()).
					Return(errors.New("unknown"))
			},
		},
		{
			testName: "AddCredential unknown error (email)",
			input: domain.RegisterInput{
				Name: "user",
				Email: "user@example.com",
				Password: "password",
				Provider: "email",
			},
			wantError: true,
			setupMock: func(){
				mockUserRepo.
					EXPECT().
					ByEmail(gomock.Eq("user@example.com")).
					Return(nil, e.UserNotFound)

				mockHashRepo.
					EXPECT().
					HashPassword(gomock.Eq("password")).
					Return("hashed password", nil)	

				mockUserRepo.
					EXPECT().
					Save(gomock.Any()).
					Return(nil)

				mockUserRepo.
					EXPECT().
					AddIdentity(gomock.Any()).
					Return(nil)

				mockUserRepo.
					EXPECT().
					AddCredential(gomock.Any()).
					Return(errors.New("unknown error"))
			},
		},
		{
			testName: "[TEMPORARILY] panic on non-email registration",
			input: domain.RegisterInput{
				Provider: "oauth",
			},
			wantPanic: true,
			setupMock: func(){},
		},
	}
	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			tt.setupMock()

			defer func(){
				if r := recover(); (r != nil) != tt.wantPanic {
					t.Errorf("RegisterUC panic (%v) != wantPanic (%v)", r != nil, tt.wantPanic)	
				}
			}()

			_, err := registerUC.Execute(tt.input)

			if (err != nil) != tt.wantError {
				t.Errorf("RegisterUC error (%v) != wantedError (%v)", err, tt.wantedError)
			}

			if err != tt.wantedError && tt.wantedError != nil {
				t.Errorf("RegisterUC error (%v) != wantedError (%v)", err, tt.wantedError)
			}
		}) 
	}
}
