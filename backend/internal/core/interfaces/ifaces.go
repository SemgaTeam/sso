package interfaces

import (
	"sso/internal/core/entities"

	"context"
	"net/http"
)

type IUser interface {
	ByID(ctx context.Context, id string) (*entities.User, error)
	ByEmail(ctx context.Context, email string) (*entities.User, error)
	ByName(ctx context.Context, name string) (*entities.User, error)
	ByIdentity(ctx context.Context, itype, externalID, issuer string) (*entities.User, error)

	Create(ctx context.Context, user *entities.User) error
	Update(ctx context.Context, user *entities.User) error

	SaveIdentity(ctx context.Context, identity *entities.Identity) error
	SaveCredential(ctx context.Context, credential *entities.Credential) error
}

type IClient interface {
	ByID(ctx context.Context, id string) (*entities.Client, error)
}

type IOAuth interface {
	HandleAuthorize(ctx context.Context, req *http.Request, rw http.ResponseWriter, userID string) error
	HandleAccess(ctx context.Context, req *http.Request, rw http.ResponseWriter) error
	IntrospectAccessToken(ctx context.Context, rw http.ResponseWriter, token string) (*entities.AccessTokenInfo, error)
}

type IToken interface {
	Generate(claims *entities.Claims) (string, error)
	SignWithKey(claims *entities.Claims, key entities.PrivateKey) (string, error)
}

type IHash interface {
	HashPassword(raw string) (string, error)
	CheckPassword(raw, hash string) error
}

type IPrivateKeys interface {
	GetPrivateKeys() ([]entities.PrivateKey, error)
	SavePrivateKey(*entities.PrivateKey) error
	Generate(name string) (*entities.PrivateKey, error)
}
