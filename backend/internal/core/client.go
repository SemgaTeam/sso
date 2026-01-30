package core

import (
	"slices"
	"time"
)

// all clients are confidential by now
type Client struct {
	ID string `json:"id"`
	Name string
	ClientID string
	RedirectURIs []string
	Status string
	CreatedAt time.Time
}

func (c *Client) AllowsRedirect(uri string) bool {
	return slices.Contains(c.RedirectURIs, uri)
}
