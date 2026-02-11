package core

import (
	e "sso/internal/core/errors"

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
	client, err := w.client.ByID(ctx, clientID)
	if err != nil {
		return "", "", err
	}

	if client == nil {
		return "", "", e.ClientNotFound
	}

	if !client.AllowsRedirect(redirectURI) {
		return "", "", e.RedirectURINotAllowed
	}

	accessClaims, err := NewClaims(client.ID, userID, w.accessExpiration)
	if err != nil {
		return "", "", err
	}

	refreshClaims, err := NewClaims(client.ID, userID, w.refreshExpiration)
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
