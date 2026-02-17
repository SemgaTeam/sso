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
	authCodeExpiration int
}

func NewOAuthWorkflow(clientInterface IClient, tokenInterface IToken, keyInterface IPrivateKeys, codesInterface IAuthCodes, accessExpiration, refreshExpiration, authCodeExpiration int) *OAuthWorkflow {
	return &OAuthWorkflow{
		client: clientInterface,
		token: tokenInterface,
		keys: keyInterface,
		authCodes: codesInterface,
		accessExpiration: accessExpiration,
		refreshExpiration: refreshExpiration,
		authCodeExpiration: authCodeExpiration,
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

	code, err := w.authCodes.Issue(client.ID, redirectURI, userID, w.authCodeExpiration)
	if err != nil {
		log.Fatal("failed to issue authentication code", zap.Error(err))
		return "", err
	}

	return redirectURI + "?code=" + code, nil
}

func (w *OAuthWorkflow) ExchangeCode(ctx context.Context, authCode, clientID, clientSecret, redirectURI, userID string) (string, string, error) {
	log := getLoggerFromContext(ctx)

	client, err := w.client.ByID(ctx, clientID)
	if err != nil {
		log.Fatal("failed to get client", zap.Error(err))
		return "", "", err
	}

	if client == nil {
		log.Info("client not found")
		return "", "", e.ClientNotFound
	}

	codeClientID, codeRedirectURI, codeUserID, err := w.authCodes.Get(authCode)
	if err != nil {
		log.Fatal("failed to get auth code", zap.Error(err))
		return "", "", err
	}

	if codeClientID == "" || codeRedirectURI == "" || codeUserID == "" {
		log.Info("auth code not found", zap.String("code", authCode))
		return "", "", e.AuthCodeNotFound
	}


	if clientID != codeClientID || redirectURI != codeRedirectURI || userID != codeUserID || client.ClientSecret != clientSecret {
		log.Info("invalid auth code", zap.String("code", authCode))
		return "", "", e.InvalidAuthCode
	}

	return w.tokens(ctx, clientID, userID)
}

func (w *OAuthWorkflow) tokens(ctx context.Context, clientID, userID string) (string, string, error) {
	log := getLoggerFromContext(ctx)

	accessClaims, err := NewClaims(clientID, userID, w.accessExpiration)
	if err != nil {
		log.Info("invalid claims", zap.Error(err))
		return "", "", err
	}

	refreshClaims, err := NewClaims(clientID, userID, w.refreshExpiration)
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
		log.Fatal("failed to sign token", zap.Error(err))
		return "", "", err
	}

	refreshToken, err := w.token.SignWithKey(refreshClaims, key)
	if err != nil {
		log.Fatal("failed to sign token", zap.Error(err))
		return "", "", err
	}

	return accessToken, refreshToken, nil
}
