package test

import (
	"sso/internal/core"
	"sso/internal/infrastructure"
	"github.com/stretchr/testify/require"

	"context"
	"crypto/rand"
	"crypto/rsa"
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

	codesRepo := infrastructure.NewAuthCodesInterface()

	accessExpiration := 60*60
	refreshExpiration := 60*60*24

	oauthWorkflow := core.NewOAuthWorkflow(clientRepo, tokenRepo, keyRepo, codesRepo, accessExpiration, refreshExpiration)

	ctx := context.Background()
	userID := "user_id"

	authCode, err := oauthWorkflow.Execute(ctx, userID, "id1", "test.client.com")

	require.NoError(t, err)
	require.NotEmpty(t, authCode)

	t.Logf("refresh: %s", authCode)
}
