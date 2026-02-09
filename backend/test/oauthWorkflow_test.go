package test

import (
	"sso/internal/core"
	"github.com/stretchr/testify/require"

	"crypto/rand"
	"crypto/rsa"
	"context"
	"testing"
	"time"
)

func TestOAuthWorkflowSuccess(t *testing.T) {
	clients := []core.Client{
		{
			ID: "1",
			Name: "test1",
			ClientID: "id1",
			RedirectURIs: []string{"test.client.com"},
			Status: "active",
			CreatedAt: time.Now(),
		},
	}

	clientRepo := &FakeClientRepository{
		clients,
	}
	tokenRepo := &FakeTokenRepository{}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Errorf("private key create error %v", err)	
	}

	keyRepo := &FakeKeyRepository{
		keys: []core.PrivateKey{
			{
				Value: *privateKey,
				Name: "test_key",
			},
		},
	}

	accessExpiration := 60*60
	refreshExpiration := 60*60*24

	oauthWorkflow := core.NewOAuthWorkflow(clientRepo, tokenRepo, keyRepo, accessExpiration, refreshExpiration)

	ctx := context.Background()
	userID := "user_id"

	accessToken, refreshToken, err := oauthWorkflow.Execute(ctx, userID, "id1", "test.client.com")

	require.NoError(t, err)
	require.NotEmpty(t, accessToken)
	require.NotEmpty(t, refreshToken)

	t.Logf("access: %s", accessToken)
	t.Logf("refresh: %s", refreshToken)
}
