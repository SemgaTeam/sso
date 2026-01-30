package infrastructure

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"sso/internal/core"

	"context"
	"time"
)

type ClientInterface struct {
	pool *pgxpool.Pool
}

func NewClientInterface(pool *pgxpool.Pool) *ClientInterface {
	return &ClientInterface{
		pool: pool,
	}
}

func (i *ClientInterface) ByID(ctx context.Context, clientID string) (*core.Client, error) {
	var id, name, status string
	var redirectURIs []string
	var createdAt time.Time

	err := i.pool.QueryRow(ctx, 
		"SELECT id, name, status, redirect_uris, created_at FROM clients WHERE client_id = $1",
		clientID,
	).Scan(&id, &name, &status, &redirectURIs, &createdAt)

	if err != nil {
		return nil, err
	}

	client := core.Client{
		ID: id,
		Name: name,
		Status: status,
		RedirectURIs: redirectURIs,
		CreatedAt: createdAt,
	}

	return &client, err
}
