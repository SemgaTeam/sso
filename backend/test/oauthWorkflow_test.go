package test

import (
	"github.com/stretchr/testify/require"
	"sso/internal/core"

	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestOAuthWorkflowSuccess(t *testing.T) {
	clients := []core.Client{
		{
			ID:           "1",
			Name:         "test1",
			ClientID:     "id1",
			RedirectURIs: []string{"https://test.client.com"},
			Status:       "active",
			CreatedAt:    time.Now(),
		},
	}

	clientRepo := &FakeClientRepository{
		clients,
	}
	accessExpiration := 60 * 60
	refreshExpiration := 60 * 60 * 24
	authCodeExpiration := 5 * 60

	oauthWorkflow := core.NewOAuthWorkflow(clientRepo, "test-secret", accessExpiration, refreshExpiration, authCodeExpiration)

	ctx := context.Background()
	userID := "user_id"

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+url.Values{
		"response_type": {"code"},
		"client_id":     {"id1"},
		"redirect_uri":  {"https://test.client.com"},
		"state":         {"state1234"},
	}.Encode(), nil)
	rr := httptest.NewRecorder()
	err := oauthWorkflow.WriteAuthorizeResponse(ctx, req, rr, userID)

	require.NoError(t, err)
	require.Equal(t, http.StatusSeeOther, rr.Code)

	redirect, err := url.Parse(rr.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "https", redirect.Scheme)
	require.Equal(t, "test.client.com", redirect.Host)
	t.Logf("redirect query: %s", redirect.RawQuery)
	require.NotEmpty(t, redirect.Query().Get("code"))

	t.Logf("redirect: %s", rr.Header().Get("Location"))
}
