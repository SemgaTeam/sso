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
}

func NewRegisterUseCase(userInterface IUser, tokenInterface IToken, hashInterface IHash) *RegisterUseCase {
	return &RegisterUseCase{
		user: userInterface,
		token: tokenInterface,
		hash: hashInterface,
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
		user, err = uc.googleOAuth(ctx, input)
	}

	if err != nil {
		return "", err
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

func (uc *RegisterUseCase) googleOAuth(ctx context.Context, input RegisterInput) (*User, error) {
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

		identity, err := NewIdentity(input.Provider, input.ExternalID, input.Issuer)
		if err != nil {
			return nil, err
		}
		identity.UserID = user.ID

		credential, err := NewCredential("oauth", payload["raw"])
		if err != nil {
			return nil, err
		}

		err = uc.user.SaveIdentity(ctx, identity)
		if err != nil {
			return nil, err
		}
		credential.IdentityID = identity.ID

		err = uc.user.SaveCredential(ctx, credential)
		if err != nil {
			return nil, err
		}
	}

	return user, nil
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
