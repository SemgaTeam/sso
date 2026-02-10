package core

import (
	"github.com/golang-jwt/jwt/v5"

	"context"
	"time"
)

type RegisterUseCase struct {
	user IUser
	token IToken
	hash IHash
	sessionExp int
}

func NewRegisterUseCase(user IUser, token IToken, hash IHash, sessionExp int) *RegisterUseCase {
	return &RegisterUseCase{
		user,
		token,
		hash,
		sessionExp,
	}
}

type RegisterInput struct {
	Provider string

	Name string
	Email string
	Password string

	ExternalID string
	Token map[string]string
	Issuer string
}

func (uc *RegisterUseCase) Execute(ctx context.Context, input RegisterInput) (string, error) {
	var user *User
	var err error

	switch input.Provider {
	case "email":
		user, err = uc.registerByEmail(ctx, input)
	
	case "oauth":
		token := input.Token
		email := token["email"]
		user, err = GoogleOAuth(ctx, uc.user, email, token["raw"], input.Provider, input.ExternalID, input.Issuer)
	}

	if err != nil {
		return "", err
	}

	issuedAt := jwt.NewNumericDate(time.Now())
	expiresAt := jwt.NewNumericDate(time.Now().Add(time.Duration(uc.sessionExp)*time.Second))

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: user.ID,
			Issuer: "sso.semgateam.ru",
			IssuedAt: issuedAt,
			ExpiresAt: expiresAt,
		},
	}

	ssoSessionToken, err := uc.token.Generate(&claims)

	return ssoSessionToken, err
}

func (uc *RegisterUseCase) registerByEmail(ctx context.Context, input RegisterInput) (*User, error) {
	user, err := NewUser(input.Name, input.Email)
	if err != nil {
		return nil, err
	}

	hashed, err := uc.hash.HashPassword(input.Password)
	if err != nil {
		return nil, err
	}

	identity, err := NewIdentity("email", user.Email, "sso.semgateam.ru")
	if err != nil {
		return nil, err
	}

	credential, err := NewCredential("password", hashed)
	if err != nil {
		return nil, err
	}

	err = uc.user.Create(ctx, user)
	if err != nil {
		return nil, err
	}

	identity.UserID = user.ID

	if err := uc.user.SaveIdentity(ctx, identity); err != nil {
		return nil, err
	}

	credential.IdentityID = identity.ID
	if err := uc.user.SaveCredential(ctx, credential); err != nil {
		return nil, err
	}

	return user, nil
}
