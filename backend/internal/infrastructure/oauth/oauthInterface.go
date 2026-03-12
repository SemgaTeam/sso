package oauth

import (
	"sso/internal/core/entities"
	i "sso/internal/core/interfaces"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"

	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"time"
)

type OAuthInterface struct {
	oauth2        fosite.OAuth2Provider
	allowedScopes map[string]struct{}
}

func NewOAuthInterface(clientInterface i.IClient, globalSecret string, accessExpiration, refreshExpiration, authCodeExpiration int) *OAuthInterface {
	normalizedSecret := normalizeGlobalSecret(globalSecret)

	cfg := &fosite.Config{
		AccessTokenLifespan:        time.Duration(accessExpiration) * time.Second,
		RefreshTokenLifespan:       time.Duration(refreshExpiration) * time.Second,
		AuthorizeCodeLifespan:      time.Duration(authCodeExpiration) * time.Second,
		GlobalSecret:               normalizedSecret,
		RefreshTokenScopes:         []string{},
		ClientSecretsHasher:        plaintextHasher{},
		SendDebugMessagesToClients: true,
	}

	storage := newOAuthStorage(clientInterface)
	oauth2 := compose.Compose(
		cfg,
		storage,
		compose.NewOAuth2HMACStrategy(cfg),
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2RefreshTokenGrantFactory,
	)

	return &OAuthInterface{
		oauth2: oauth2,
		allowedScopes: map[string]struct{}{
			"profile": {},
			"email":   {},
			"status":  {},
		},
	}
}

func normalizeGlobalSecret(secret string) []byte {
	raw := []byte(secret)
	if len(raw) >= 32 {
		return raw
	}

	sum := sha256.Sum256(raw)
	return sum[:]
}

func (w *OAuthInterface) HandleAuthorize(ctx context.Context, req *http.Request, rw http.ResponseWriter, userID string) error {
	ar, err := w.oauth2.NewAuthorizeRequest(ctx, req)
	if err != nil {
		w.oauth2.WriteAuthorizeError(ctx, rw, ar, err)
		return nil
	}

	clientScopes := ar.GetClient().GetScopes()
	for _, scope := range ar.GetRequestedScopes() {
		if _, exists := w.allowedScopes[scope]; !exists {
			w.oauth2.WriteAuthorizeError(ctx, rw, ar, fosite.ErrInvalidScope.WithHintf("scope '%s' is not supported", scope))
			return nil
		}
		if !clientScopes.Has(scope) {
			w.oauth2.WriteAuthorizeError(ctx, rw, ar, fosite.ErrInvalidScope.WithHintf("client is not allowed to request scope '%s'", scope))
			return nil
		}
	}

	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}

	resp, err := w.oauth2.NewAuthorizeResponse(ctx, ar, &fosite.DefaultSession{
		Subject: userID,
	})
	if err != nil {
		w.oauth2.WriteAuthorizeError(ctx, rw, ar, err)
		return nil
	}

	w.oauth2.WriteAuthorizeResponse(ctx, rw, ar, resp)
	return nil
}

func (w *OAuthInterface) HandleAccess(ctx context.Context, req *http.Request, rw http.ResponseWriter) error {
	ar, err := w.oauth2.NewAccessRequest(ctx, req, new(fosite.DefaultSession))
	if err != nil {
		w.oauth2.WriteAccessError(ctx, rw, ar, err)
		return nil
	}

	resp, err := w.oauth2.NewAccessResponse(ctx, ar)
	if err != nil {
		w.oauth2.WriteAccessError(ctx, rw, ar, err)
		return nil
	}

	w.oauth2.WriteAccessResponse(ctx, rw, ar, resp)
	return nil
}

func (w *OAuthInterface) IntrospectAccessToken(ctx context.Context, rw http.ResponseWriter, token string) (*entities.AccessTokenInfo, error) {
	_, requester, err := w.oauth2.IntrospectToken(ctx, token, fosite.AccessToken, new(fosite.DefaultSession))
	if err != nil {
		w.oauth2.WriteIntrospectionError(ctx, rw, err)
		return nil, err
	}

	session := requester.GetSession()
	if session == nil {
		return nil, errors.New("token session is missing")
	}

	subject := session.GetSubject()
	if subject == "" {
		return nil, errors.New("token subject is missing")
	}

	return &entities.AccessTokenInfo{
		Subject: subject,
		Scopes:  requester.GetGrantedScopes(),
	}, nil
}

type plaintextHasher struct{}

func (plaintextHasher) Compare(_ context.Context, hash, data []byte) error {
	if string(hash) != string(data) {
		return fosite.ErrInvalidClient
	}
	return nil
}

func (plaintextHasher) Hash(_ context.Context, data []byte) ([]byte, error) {
	return data, nil
}
