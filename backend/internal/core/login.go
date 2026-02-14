package core

import (
	e "sso/internal/core/errors"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"context"
	"time"
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
	log := getLoggerFromContext(ctx)

	var user *User
	var err error

	switch input.Provider {
	case "email":
		user, err = uc.loginByEmail(ctx, input)	
	case "oauth":
		token := input.Token
		email := token["email"]
		user, err = GoogleOAuth(ctx, uc.user, email, token["raw"], input.Provider, input.ExternalID, input.Issuer)
	default:
		err = e.InvalidAuthProvider
	}

	if err != nil {
		return "", err
	}

	if !user.CanLogin() {
		log.Info("user cannot be logged in", zap.String("user_id", user.ID), zap.String("status", user.Status))
		return "", e.UserCannotBeLoggedIn
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
	log := getLoggerFromContext(ctx)

	user, err := uc.user.ByEmail(ctx, input.Email)
	if err != nil {
		log.Fatal("failed to get user by email", zap.Error(err), zap.String("email", input.Email))
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
		log.Info("identity not found", zap.String("user_id", user.ID))
		return nil, e.IdentityNotFound
	}

	var passwordCred *Credential
	for _, cred := range emailIdentity.Credentials {
		if cred.Type == "password" {
			passwordCred = &cred
		}
	}

	if passwordCred == nil {
		log.Info("credential not found", zap.String("user_id", user.ID), zap.String("identity_id", emailIdentity.ID))
		return nil, e.CredentialNotFound
	}

	if err := uc.hash.CheckPassword(input.Password, passwordCred.Hash); err != nil {
		log.Fatal("failed to check password", zap.Error(err))
		return nil, err
	}

	return user, nil
}
