package core

import (
	"sso/internal/core/entities"
	i "sso/internal/core/interfaces"

	"context"
	"crypto/sha256"
	"errors"
)

type OAuthWorkflow struct {
	user          i.IUser
	oauth2        i.IOAuth
	allowedScopes map[string]struct{}
}

func NewOAuthWorkflow(userInterface i.IUser, oauthInterface i.IOAuth) *OAuthWorkflow {
	return &OAuthWorkflow{
		user:   userInterface,
		oauth2: oauthInterface,
		allowedScopes: map[string]struct{}{
			"profile": {},
			"email":   {},
			"status":  {},
		},
	}
}

func normalizeGlobalSecret(secret string) []byte {
	raw := []byte(secret)
	if len(raw) >= 32 {
		return raw
	}

	sum := sha256.Sum256(raw)
	return sum[:]
}

func (w *OAuthWorkflow) UserInfo(ctx context.Context, tokenInfo entities.AccessTokenInfo) (map[string]any, error) {
	response := map[string]any{
		"sub": tokenInfo.Subject,
	}

	if len(tokenInfo.Scopes) != 0 {
		user, err := w.user.ByID(ctx, tokenInfo.Subject)
		if err != nil {
			return nil, err
		}
		if user == nil {
			return nil, errors.New("user not found")
		}

		for _, scope := range tokenInfo.Scopes {
			if _, exists := w.allowedScopes[scope]; !exists {
				return nil, errors.New("scope is not allowed")
			}

			switch scope {
			case "profile":
				response["name"] = user.Name
			case "email":
				response["email"] = user.Email
			case "status":
				response["status"] = user.Status
			}
		}
	}

	return response, nil
}
