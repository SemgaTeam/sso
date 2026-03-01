package core

import (
	"crypto/sha256"
	"errors"
	"sync"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/storage"

	"context"
	"net/http"
	"time"
)

type OAuthWorkflow struct {
	oauth2        fosite.OAuth2Provider
	allowedScopes map[string]struct{}
	user          IUser
}

type AccessTokenInfo struct {
	Subject string
	Scopes  []string
}

func NewOAuthWorkflow(clientInterface IClient, userInterface IUser, globalSecret string, accessExpiration, refreshExpiration, authCodeExpiration int) *OAuthWorkflow {
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
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2RefreshTokenGrantFactory,
	)

	return &OAuthWorkflow{
		oauth2: oauth2,
		allowedScopes: map[string]struct{}{
			"profile": {},
			"email":   {},
			"status":  {},
		},
		user: userInterface,
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

func (w *OAuthWorkflow) WriteAuthorizeResponse(ctx context.Context, req *http.Request, rw http.ResponseWriter, userID string) error {
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

func (w *OAuthWorkflow) WriteAccessResponse(ctx context.Context, req *http.Request, rw http.ResponseWriter) error {
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

func (w *OAuthWorkflow) AccessTokenInfoByToken(ctx context.Context, token string) (*AccessTokenInfo, error) {
	_, requester, err := w.oauth2.IntrospectToken(ctx, token, fosite.AccessToken, new(fosite.DefaultSession))
	if err != nil {
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

	return &AccessTokenInfo{
		Subject: subject,
		Scopes:  requester.GetGrantedScopes(),
	}, nil
}

func (w *OAuthWorkflow) UserInfo(ctx context.Context, token string) (map[string]any, error) {
	tokenInfo, err := w.AccessTokenInfoByToken(ctx, token)
	if err != nil {
		return nil, err
	}

	response := map[string]any{
		"sub": tokenInfo.Subject,
	}

	if len(tokenInfo.Scopes) != 0 {
		user, err := w.user.ByID(ctx, tokenInfo.Subject)
		if err != nil {
			return nil, err
		}
		if user == nil {
			return nil, errors.New("user not found")
		}

		for _, scope := range tokenInfo.Scopes {
			if _, exists := w.allowedScopes[scope]; !exists {
				return nil, errors.New("scope is not allowed")
			}

			switch scope {
			case "profile":
				response["name"] = user.Name
			case "email":
				response["email"] = user.Email
			case "status":
				response["status"] = user.Status
			}
		}
	}

	return response, nil
}

type oauthStorage struct {
	*storage.MemoryStore
	client IClient

	authorizeCodes      map[string]authorizeCodeRecord
	authorizeCodesMutex sync.RWMutex
}

type authorizeCodeRecord struct {
	active bool
	req    fosite.Requester
}

func newOAuthStorage(client IClient) *oauthStorage {
	return &oauthStorage{
		MemoryStore:    storage.NewMemoryStore(),
		client:         client,
		authorizeCodes: map[string]authorizeCodeRecord{},
	}
}

func (s *oauthStorage) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	client, err := s.client.ByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if client == nil || client.Status != "active" {
		return nil, fosite.ErrNotFound
	}

	return client, nil
}

func (s *oauthStorage) CreateAuthorizeCodeSession(_ context.Context, code string, request fosite.Requester) error {
	s.authorizeCodesMutex.Lock()
	defer s.authorizeCodesMutex.Unlock()

	s.authorizeCodes[code] = authorizeCodeRecord{
		active: true,
		req:    request,
	}

	return nil
}

func (s *oauthStorage) GetAuthorizeCodeSession(_ context.Context, code string, _ fosite.Session) (fosite.Requester, error) {
	s.authorizeCodesMutex.RLock()
	defer s.authorizeCodesMutex.RUnlock()

	record, exists := s.authorizeCodes[code]
	if !exists {
		return nil, fosite.ErrNotFound
	}

	if !record.active {
		return record.req, fosite.ErrInvalidatedAuthorizeCode
	}

	return record.req, nil
}

func (s *oauthStorage) InvalidateAuthorizeCodeSession(_ context.Context, code string) error {
	s.authorizeCodesMutex.Lock()
	defer s.authorizeCodesMutex.Unlock()

	record, exists := s.authorizeCodes[code]
	if !exists {
		return fosite.ErrNotFound
	}

	record.active = false
	s.authorizeCodes[code] = record

	return nil
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
