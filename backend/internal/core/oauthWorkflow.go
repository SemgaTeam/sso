package core

import (
	e "sso/internal/core/errors"
	"go.uber.org/zap"

	"context"
)

type OAuthWorkflow struct {
	client IClient
	token IToken
	keys IPrivateKeys

	accessExpiration int
	refreshExpiration int
}

func NewOAuthWorkflow(clientInterface IClient, tokenInterface IToken, keyInterface IPrivateKeys, accessExpiration, refreshExpiration int) *OAuthWorkflow {
	return &OAuthWorkflow{
		client: clientInterface,
		token: tokenInterface,
		keys: keyInterface,
		accessExpiration: accessExpiration,
		refreshExpiration: refreshExpiration,
	}
}

func (w *OAuthWorkflow) Execute(ctx context.Context, userID, clientID, redirectURI string) (string, string, error) {
	log := getLoggerFromContext(ctx)

	client, err := w.client.ByID(ctx, clientID)
	if err != nil {
		log.Fatal("failed to get client by id", zap.Error(err), zap.String("client_id", clientID))
		return "", "", err
	}

	if client == nil {
		log.Info("client not found", zap.String("client_id", clientID))
		return "", "", e.ClientNotFound
	}

	if !client.AllowsRedirect(redirectURI) {
		log.Info("redirect is not allowed", zap.String("client_id", clientID), zap.String("redirect_uri", redirectURI))
		return "", "", e.RedirectURINotAllowed
	}

	accessClaims, err := NewClaims(client.ID, userID, w.accessExpiration)
	if err != nil {
		log.Info("invalid claims", zap.Error(err))
		return "", "", err
	}

	refreshClaims, err := NewClaims(client.ID, userID, w.refreshExpiration)
	if err != nil {
		log.Info("invalid claims", zap.Error(err))
		return "", "", err
	}

	keys, err := w.keys.GetPrivateKeys()
	if err != nil {
		log.Fatal("failed to get private keys", zap.Error(err))
		return "", "", err
	}
	if len(keys) == 0 {
		log.Fatal("no private keys found")
		return "", "", e.KeysNotFound
	}

	key := keys[0]
	
	accessToken, err := w.token.SignWithKey(accessClaims, key)
	if err != nil {
		log.Fatal("failed to sign a token")
		return "", "", err
	}

	refreshToken, err := w.token.SignWithKey(refreshClaims, key)
	if err != nil {
		log.Fatal("failed to sign a token")
		return "", "", err
	}

	return accessToken, refreshToken, nil
}
