package domain

import (
	"github.com/SemgaTeam/sso/internal/entities"
)

func AllowsRedirect(client *entities.Client, redirectURI string) bool {
	res := false
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			res = true
		}
	}

	return res
}
