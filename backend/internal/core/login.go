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
}

func NewLoginUseCase(user IUser, token IToken, hash IHash) *LoginUseCase {
	return &LoginUseCase{
		user,
		token,
		hash,
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
		user, err = uc.googleOAuth(ctx, input)
	}

	if err != nil {
		return "", err
	}

	if !user.CanLogin() {
		return "", errors.New("user cannot be logged in")
	}

	sessionTokenExp := 3600

	issuedAt := jwt.NewNumericDate(time.Now())
	expiresAt := jwt.NewNumericDate(time.Now().Add(time.Duration(sessionTokenExp)*time.Second))

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

func (uc *LoginUseCase) googleOAuth(ctx context.Context, input LoginInput) (*User, error) {
	payload := input.Token

	email := payload["email"]

	user, err := uc.user.ByIdentity(ctx, input.Provider, input.ExternalID, input.Issuer)	
	if err != nil {
		return nil, err
	}

	if user == nil {
		user, err = uc.user.ByEmail(ctx, email)	
		if err != nil {
			return nil, err
		}

		if user == nil {
			name := email	

			user, err = NewUser(name, email)
			if err != nil {
				return nil, err
			}

			err = uc.user.Create(ctx, user)
			if err != nil {
				return nil, err
			}
		} 

		identity, err := NewIdentity(user.ID, input.Provider, input.ExternalID, input.Issuer)
		if err != nil {
			return nil, err
		}

		credential, err := NewCredential("oauth", payload["raw"])
		if err != nil {
			return nil, err
		}

		err = uc.user.SaveIdentity(ctx, identity)
		if err != nil {
			return nil, err
		}

		err = uc.user.SaveCredential(ctx, credential)
		if err != nil {
			return nil, err
		}
	}

	return user, nil
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
