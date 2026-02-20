package test

import (
	"sso/internal/core"
	"github.com/stretchr/testify/require"

	"context"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"
)

func TestOAuthWorkflowExchangeCodeSuccess(t *testing.T) {
	clients := []core.Client{
		{
			ID:           "1",
			Name:         "test1",
			ClientID:     "id1",
			ClientSecret: "secret1",
			RedirectURIs: []string{"https://test.client.com/callback"},
			Status:       "active",
			CreatedAt:    time.Now(),
		},
	}

	clientRepo := &FakeClientRepository{clients}
	tokenRepo := &FakeTokenRepository{}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Errorf("private key create error %v", err)
	}

	keyRepo := &FakeKeyRepository{
		keys: []core.PrivateKey{
			{
				Value: *privateKey,
				Name:  "test_key",
			},
		},
	}

	codesRepo := &FakeAuthCodesRepository{}

	accessExpiration := 60 * 60
	refreshExpiration := 60 * 60 * 24
	authCodeExpiration := 5 * 60

	oauthWorkflow := core.NewOAuthWorkflow(clientRepo, tokenRepo, keyRepo, codesRepo, accessExpiration, refreshExpiration, authCodeExpiration)

	ctx := context.Background()
	userID := "user_id"
	clientID := "id1"
	clientSecret := "secret1"
	redirectURI := "https://test.client.com/callback"

	redirectWithCode, err := oauthWorkflow.Execute(ctx, userID, clientID, redirectURI)
	require.NoError(t, err)

	code, ok := strings.CutPrefix(redirectWithCode, redirectURI+"?code=")
	require.True(t, ok)
	require.NotEmpty(t, code)

	accessToken, refreshToken, err := oauthWorkflow.ExchangeCode(ctx, code, clientID, clientSecret, redirectURI, userID)
	require.NoError(t, err)
	require.NotEmpty(t, accessToken)
	require.NotEmpty(t, refreshToken)
}
