package infrastructure

import (
	"sso/internal/core"
	e "sso/internal/core/errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"context"
	"errors"
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
	var clientSecret string
	var createdAt time.Time

	err := i.pool.QueryRow(ctx,
		"SELECT id, name, status, redirect_uris, client_secret, created_at FROM clients WHERE client_id = $1",
		clientID,
	).Scan(&id, &name, &status, &redirectURIs, &clientSecret, &createdAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		} else {
			return nil, e.Unknown(err)
		}
	}

	client := core.Client{
		ID:           id,
		Name:         name,
		Status:       status,
		RedirectURIs: redirectURIs,
		ClientSecret: clientSecret,
		CreatedAt:    createdAt,
	}

	return &client, nil
}
