package test

import (
	"encoding/json"
	"sso/internal/core"

	"github.com/stretchr/testify/require"

	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestOAuthWorkflowSuccess(t *testing.T) {
	clients := []core.Client{
		{
			ID:           "1",
			Name:         "test1",
			ClientID:     "id1",
			ClientSecret: "secret1",
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

func TestWriteAccessResponseSuccess(t *testing.T) {
	clients := []core.Client{
		{
			ID:           "1",
			Name:         "test1",
			ClientID:     "id1",
			ClientSecret: "secret1",
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

	authorizeReq := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+url.Values{
		"response_type": {"code"},
		"client_id":     {"id1"},
		"redirect_uri":  {"https://test.client.com"},
		"state":         {"state1234"},
	}.Encode(), nil)
	authorizeResp := httptest.NewRecorder()
	err := oauthWorkflow.WriteAuthorizeResponse(ctx, authorizeReq, authorizeResp, "user_id")
	require.NoError(t, err)
	require.Equal(t, http.StatusSeeOther, authorizeResp.Code)

	redirect, err := url.Parse(authorizeResp.Header().Get("Location"))
	require.NoError(t, err)
	code := redirect.Query().Get("code")
	require.NotEmpty(t, code)

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {"https://test.client.com"},
	}
	accessReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	accessReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	accessReq.SetBasicAuth("id1", "secret1")
	accessResp := httptest.NewRecorder()

	err = oauthWorkflow.WriteAccessResponse(ctx, accessReq, accessResp)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, accessResp.Code)

	payload := map[string]any{}
	err = json.Unmarshal(accessResp.Body.Bytes(), &payload)
	require.NoError(t, err)
	require.NotEmpty(t, payload["access_token"])
	require.NotEmpty(t, payload["refresh_token"])
	t.Logf("access_token: %s", payload["access_token"])
	t.Logf("refresh_token: %s", payload["refresh_token"])
	require.Equal(t, "bearer", payload["token_type"])
}
