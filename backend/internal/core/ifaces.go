package core

import (
	"context"
	"crypto/rsa"
)

type IUser interface {
	ByID(ctx context.Context, id string) (*User, error)
	ByEmail(ctx context.Context, email string) (*User, error)
	ByName(ctx context.Context, name string) (*User, error)
	ByIdentity(ctx context.Context, itype, externalID, issuer string) (*User, error)

	Create(ctx context.Context, user *User) error
	Update(ctx context.Context, user *User) error

	SaveIdentity(ctx context.Context, identity *Identity) error
	SaveCredential(ctx context.Context, credential *Credential) error
}

type IClient interface {
	ByID(ctx context.Context, id string) (*Client, error)
}

type IToken interface {
	Generate(claims *Claims) (string, error)
}

type IHash interface {
	HashPassword(raw string) (string, error)
	CheckPassword(raw, hash string) error
}

type IPrivateKeys interface {
	GetPrivateKeys() ([]rsa.PrivateKey, error)
	SavePrivateKey(*PrivateKey) error
}
