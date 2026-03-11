package oauth

import (
	i "sso/internal/core/interfaces"

	"context"
	"sync"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
)

type oauthStorage struct {
	*storage.MemoryStore
	client i.IClient

	authorizeCodes      map[string]authorizeCodeRecord
	authorizeCodesMutex sync.RWMutex
}

type authorizeCodeRecord struct {
	active bool
	req    fosite.Requester
}

func newOAuthStorage(client i.IClient) *oauthStorage {
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
