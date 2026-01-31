package core

import (
	"github.com/stretchr/testify/require"

	"context"
	"fmt"
	"testing"
	"time"
)

type FakeClientRepository struct {
	clients []Client
}

func (r *FakeClientRepository) ByID(ctx context.Context, id string) (*Client, error) {
	for _, c := range r.clients {
		if c.ClientID == id {
			return &c, nil
		}
	}

	return nil, nil
}

type FakeTokenRepository struct {}
func (r *FakeTokenRepository) Generate(claims *Claims) (string, error) {
	return fmt.Sprintf("%v", claims), nil
}

func TestOAuthWorkflowSuccess(t *testing.T) {
	clients := []Client{
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

	oauthWorkflow := NewOAuthWorkflow(clientRepo, tokenRepo, accessExpiration, refreshExpiration)

	ctx := context.Background()
	userID := "user_id"

	accessToken, refreshToken, err := oauthWorkflow.Execute(ctx, userID, "id1", "test.client.com")

	require.NoError(t, err)
	require.NotEmpty(t, accessToken)
	require.NotEmpty(t, refreshToken)
}
