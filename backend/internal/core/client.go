package core

import (
	"github.com/ory/fosite"
	"slices"
	"time"
)

// all clients are confidential by now
type Client struct {
	ID           string `json:"id"`
	Name         string
	ClientID     string
	ClientSecret string
	RedirectURIs []string
	Public       bool
	Status       string
	CreatedAt    time.Time
}

func (c *Client) AllowsRedirect(uri string) bool {
	return c.Status == "active" && slices.Contains(c.RedirectURIs, uri)
}

func (c *Client) GetID() string {
	return c.ClientID
}

func (c *Client) GetHashedSecret() []byte {
	return []byte(c.ClientSecret)
}

func (c *Client) GetRedirectURIs() []string {
	return slices.Clone(c.RedirectURIs)
}

func (c *Client) GetGrantTypes() fosite.Arguments {
	return fosite.Arguments{"authorization_code", "refresh_token"}
}

func (c *Client) GetResponseTypes() fosite.Arguments {
	return fosite.Arguments{"code"}
}

func (c *Client) GetScopes() fosite.Arguments {
	return nil
}

func (c *Client) IsPublic() bool {
	return c.Public
}

func (c *Client) GetAudience() fosite.Arguments {
	return nil
}
