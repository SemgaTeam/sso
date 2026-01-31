package test

import (
	"github.com/stretchr/testify/require"
	"sso/internal/core"

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

	accessExpiration := 60*60
	refreshExpiration := 60*60*24

	oauthWorkflow := core.NewOAuthWorkflow(clientRepo, tokenRepo, accessExpiration, refreshExpiration)

	ctx := context.Background()
	userID := "user_id"

	accessToken, refreshToken, err := oauthWorkflow.Execute(ctx, userID, "id1", "test.client.com")

	require.NoError(t, err)
	require.NotEmpty(t, accessToken)
	require.NotEmpty(t, refreshToken)
}
