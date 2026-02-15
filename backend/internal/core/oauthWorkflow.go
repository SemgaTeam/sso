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
	authCodes IAuthCodes

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

func (w *OAuthWorkflow) Execute(ctx context.Context, userID, clientID, redirectURI string) (string, error) {
	log := getLoggerFromContext(ctx)

	client, err := w.client.ByID(ctx, clientID)
	if err != nil {
		log.Fatal("failed to get client by id", zap.Error(err), zap.String("client_id", clientID))
		return "", err
	}

	if client == nil {
		log.Info("client not found", zap.String("client_id", clientID))
		return "", e.ClientNotFound
	}

	if !client.AllowsRedirect(redirectURI) {
		log.Info("redirect is not allowed", zap.String("client_id", clientID), zap.String("redirect_uri", redirectURI))
		return "", e.RedirectURINotAllowed
	}

	authCodeTTL := 5*60
	code, err := w.authCodes.Issue(client.ID, redirectURI, userID, authCodeTTL)
	if err != nil {
		log.Fatal("failed to issue access token", zap.Error(err))
		return "", err
	}

	return code, nil
}

func (w *OAuthWorkflow) returnTokens(clientID, userID string) (string, string, error) {
	accessClaims, err := NewClaims(clientID, userID, w.accessExpiration)
	if err != nil {
		return "", "", err
	}

	refreshClaims, err := NewClaims(clientID, userID, w.refreshExpiration)
	if err != nil {
		return "", "", err
	}

	keys, err := w.keys.GetPrivateKeys()
	if err != nil {
		return "", "", err
	}
	if len(keys) == 0 {
		return "", "", e.KeysNotFound
	}

	key := keys[0]
	
	accessToken, err := w.token.SignWithKey(accessClaims, key)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := w.token.SignWithKey(refreshClaims, key)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}
