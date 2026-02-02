package test

import (
	"sso/internal/core"

	"context"
	"fmt"
	"errors"
)

type FakeClientRepository struct {
	clients []core.Client
}

func (r *FakeClientRepository) ByID(ctx context.Context, id string) (*core.Client, error) {
	for _, c := range r.clients {
		if c.ClientID == id {
			return &c, nil
		}
	}

	return nil, nil
}

type FakeTokenRepository struct {}
func (r *FakeTokenRepository) Generate(claims *core.Claims) (string, error) {
	return fmt.Sprintf("%v", claims), nil
}

type FakeUserRepository struct {
	users []core.User
	identities []core.Identity
	credentials []core.Credential
}

func (r *FakeUserRepository) preload(user *core.User) {
	for _, id := range r.identities {
		if id.UserID == user.ID {
			user.Identities = append(user.Identities, id)		
			for _, cred := range r.credentials {
				if cred.IdentityID == id.ID {
					id.Credentials = append(id.Credentials, cred)
				}
			}
		}
	}
}

func (r *FakeUserRepository) ByID(ctx context.Context, id string) (*core.User, error) {
	for i := range r.users {
		if r.users[i].ID == id {
			user := &r.users[i]
			r.preload(user)
			return user, nil
		}
	}

	return nil, nil
}

func (r *FakeUserRepository) ByEmail(ctx context.Context, email string) (*core.User, error) {
	for _, user := range r.users {
		if user.Email == email {
			r.preload(&user)
			return &user, nil
		}
	}

	return nil, nil
}

func (r *FakeUserRepository) ByName(ctx context.Context, name string) (*core.User, error) {
	for _, user := range r.users {
		if user.Name == name {
			r.preload(&user)
			return &user, nil
		}
	}

	return nil, nil
}

func (r *FakeUserRepository) ByIdentity(ctx context.Context, itype, externalID, issuer string) (*core.User, error) {
	for _, id := range r.identities {
		if id.Type == itype && id.ExternalID == externalID && id.Issuer == issuer {
			user, err := r.ByID(ctx, id.UserID)
			if err != nil {
				return nil, err
			}

			r.preload(user)

			return user, nil
		}
	}
	
	return nil, nil
}

func (r *FakeUserRepository) Create(ctx context.Context, user *core.User) error {
	user.ID = user.Name + user.Email

	r.users = append(r.users, *user)

	return nil
}

func (r *FakeUserRepository) Update(ctx context.Context, u *core.User) error {
	user, err := r.ByID(ctx, u.ID)
	if err != nil {
		return err
	}
	if user == nil {
		return errors.New("user not found")
	}

	user.Name = u.Name
	user.Email = u.Email
	user.Status = u.Status

	return nil
}

func (r *FakeUserRepository) SaveIdentity(ctx context.Context, identity *core.Identity) error {
	identity.ID = identity.Type + identity.Issuer + identity.ExternalID

	r.identities = append(r.identities, *identity)

	return nil
}

func (r *FakeUserRepository) SaveCredential(ctx context.Context, cred *core.Credential) error {
	r.credentials = append(r.credentials, *cred)

	return nil
}

type FakeHashRepository struct {}
func (r *FakeHashRepository) HashPassword(raw string) (string, error) {
	return raw + "_hashed", nil
}

func (r *FakeHashRepository) CheckPassword(raw, hash string) error {
	if (raw + "_hashed") != hash {
		return errors.New("passwords not match")
	}

	return nil
}

