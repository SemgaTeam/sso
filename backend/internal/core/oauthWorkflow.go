package core

import (
	"errors"
	"context"
)

type OAuthWorkflow struct {
	client IClient
	token IToken

	accessExpiration int
	refreshExpiration int
}

func NewOAuthWorkflow(clientInterface IClient, tokenInterface IToken, accessExpiration, refreshExpiration int) *OAuthWorkflow {
	return &OAuthWorkflow{
		client: clientInterface,
		token: tokenInterface,
		accessExpiration: accessExpiration,
		refreshExpiration: refreshExpiration,
	}
}

func (w *OAuthWorkflow) Execute(ctx context.Context, userID, clientID, redirectURI string) (string, string, error) {
	client, err := w.client.ByID(ctx, clientID)
	if err != nil {
		return "", "", err
	}

	if !client.AllowsRedirect(redirectURI) {
		return "", "", errors.New("redirect uri is not allowed")
	}

	accessClaims, err := NewClaims(client.ID, userID, w.accessExpiration)
	if err != nil {
		return "", "", err
	}

	refreshClaims, err := NewClaims(client.ID, userID, w.refreshExpiration)
	if err != nil {
		return "", "", err
	}

	accessToken, err := w.token.Generate(accessClaims)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := w.token.Generate(refreshClaims)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}
