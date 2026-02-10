package core

import (
	"github.com/golang-jwt/jwt/v5"

	"context"
	"time"
	"errors"
)

type LoginUseCase struct {
	user IUser
	token IToken
	hash IHash
	sessionExp int
}

func NewLoginUseCase(user IUser, token IToken, hash IHash, sessionExp int) *LoginUseCase {
	return &LoginUseCase{
		user,
		token,
		hash,
		sessionExp,
	}
}

type LoginInput struct {
	Provider string

	Email string
	Password string

	ExternalID string
	Token map[string]string
	Issuer string
}

func (uc *LoginUseCase) Execute(ctx context.Context, input LoginInput) (string, error) {
	var user *User
	var err error

	switch input.Provider {
	case "email":
		user, err = uc.loginByEmail(ctx, input)	
	case "oauth":
		token := input.Token
		email := token["email"]
		user, err = GoogleOAuth(ctx, uc.user, email, token["raw"], input.Provider, input.ExternalID, input.Issuer)
	}

	if err != nil {
		return "", err
	}

	if !user.CanLogin() {
		return "", errors.New("user cannot be logged in")
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

func (uc *LoginUseCase) loginByEmail(ctx context.Context, input LoginInput) (*User, error) {
	user, err := uc.user.ByEmail(ctx, input.Email)
	if err != nil {
		return nil, err
	}

	var emailIdentity *Identity
	for _, id := range user.Identities {
		if id.Type == "email" {
			emailIdentity = &id
			break
		}
	}

	if emailIdentity == nil {
		return nil, errors.New("no email identity")
	}

	var passwordCred *Credential
	for _, cred := range emailIdentity.Credentials {
		if cred.Type == "password" {
			passwordCred = &cred
		}
	}

	if passwordCred == nil {
		return nil, errors.New("no password credential")
	}

	if err := uc.hash.CheckPassword(input.Password, passwordCred.Hash); err != nil {
		return nil, err
	}

	return user, nil
}
