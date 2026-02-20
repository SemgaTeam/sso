package test

import (
	"github.com/golang-jwt/jwt/v5"
	"sso/internal/core"

	"crypto/rand"
	"crypto/rsa"
	"context"
	"errors"
	"fmt"
	"time"
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

func (r *FakeTokenRepository) SignWithKey(claims *core.Claims, key core.PrivateKey) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	signed, err := token.SignedString(&key.Value)
	if err != nil {
		return "", err
	}

	return signed, nil
}

type FakeKeyRepository struct {
	keys []core.PrivateKey
}

func (r *FakeKeyRepository) GetPrivateKeys() ([]core.PrivateKey, error) {
	return r.keys, nil
}

func (r *FakeKeyRepository) SavePrivateKey(key *core.PrivateKey) error {
	if key == nil {
		return errors.New("key is nil")
	}
	r.keys = append(r.keys, *key)

	return nil
}

func (r *FakeKeyRepository) Generate(name string) (*core.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	privateKey := core.PrivateKey{
		Value: *key,
		Name: name,
	}

	return &privateKey, nil
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

type fakeAuthCode struct {
	clientID    string
	redirectURI string
	userID      string
	expiresAt   time.Time
}

type FakeAuthCodesRepository struct {
	codes map[string]fakeAuthCode
}

func (r *FakeAuthCodesRepository) Issue(clientID, redirectURI, userID string, ttl int) (string, error) {
	if r.codes == nil {
		r.codes = map[string]fakeAuthCode{}
	}

	code := fmt.Sprintf("code-%d", len(r.codes)+1)
	r.codes[code] = fakeAuthCode{
		clientID:    clientID,
		redirectURI: redirectURI,
		userID:      userID,
		expiresAt:   time.Now().Add(time.Duration(ttl) * time.Second),
	}

	return code, nil
}

func (r *FakeAuthCodesRepository) Get(code string) (string, string, string, error) {
	authCode, ok := r.codes[code]
	if !ok || authCode.expiresAt.Before(time.Now()) {
		return "", "", "", nil
	}

	return authCode.clientID, authCode.redirectURI, authCode.userID, nil
}

func (r *FakeAuthCodesRepository) Delete(code string) error {
	delete(r.codes, code)
	return nil
}
