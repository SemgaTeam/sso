package infrastructure

import (
	"sso/internal/core"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"context"
)

type UserInterface struct {
	pool *pgxpool.Pool
}

func NewUserInterface(pool *pgxpool.Pool) *UserInterface {
	return &UserInterface{
		pool,
	}
}

func (i *UserInterface) ByID(ctx context.Context, id string) (*core.User, error) {
	var name string
	var email string
	var status string

	err := i.pool.QueryRow(ctx, 
	"SELECT name, email, status FROM users WHERE id = $1 AND status <> 'deleted'",
		id,
	).Scan(&name, &email, &status)
	if err != nil {
		return nil, err
	}

	user := core.User{
		ID: id,
		Name: name,
		Email: email,
		Status: status,
	}

	return &user, nil
}

func (i *UserInterface) ByIdentity(ctx context.Context, itype, externalID, issuer string) (*core.User, error) {
	var id string
	var name string
	var email string
	var status string

	err := i.pool.QueryRow(ctx, 
		`SELECT u.id, u.name, u.email, u.status 
		 FROM users u
		 JOIN identities i ON u.id = i.user_id
		 WHERE i.type = $1 AND i.external_id = $2 AND i.issuer = $3`,
		itype, externalID, issuer,
	).Scan(&id, &name, &email, &status)

	if err != nil {
		return nil, err
	}

	user := core.User{
		ID: id,
		Name: name,
		Email: email,
		Status: status,
	}

	return &user, nil
}

func (i *UserInterface) ByEmail(ctx context.Context, email string) (*core.User, error) {
	var id string
	var name string
	var status string

	err := i.pool.QueryRow(ctx,
		"SELECT id, name, status FROM users WHERE email = $1 AND status <> 'deleted'",
		email,
	).Scan(&id, &name, &status)

	if err != nil {
		return nil, err
	}

	user := core.User{
		ID: id,
		Name: name,
		Email: email,
		Status: status,
	}

	return &user, nil
}

func (i *UserInterface) ByName(ctx context.Context, name string) (*core.User, error) {
	var id string
	var email string
	var status string

	err := i.pool.QueryRow(ctx, 
	"SELECT id, email, status FROM users WHERE name = $1 AND status <> 'deleted'",
		name,
	).Scan(&id, &email, &status)

	if err != nil {
		return nil, err
	}

	user := core.User{
		ID: id,
		Name: name,
		Email: email,
		Status: status,
	}

	return &user, nil
}

func (i *UserInterface) Create(ctx context.Context, user *core.User) error {
	var id string
	err := i.pool.QueryRow(ctx,
		"INSERT INTO users(name, email) VALUES ($1, $2) RETURNING id",
		user.Name,
		user.Email,
	).Scan(&id)

	if err != nil {
		return err
	}

	user.ID = id

	return nil
}

func (i *UserInterface) Update(ctx context.Context, user *core.User) error {
	_, err := i.pool.Exec(ctx, 
		"UPDATE users SET name = $1, email = $2, status = $3 WHERE id = $4", 
		user.Name,
		user.Email,
		user.Status,
		user.ID,
	)

	return err
}

func (i *UserInterface) CheckPassword(ctx context.Context, userID, rawPassword string) error {
	hash, err := i.getHash(ctx, userID)
	if err != nil {
		return err
	}

	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(rawPassword))		
	if err != nil {
		return err
	}

	return nil
}

func (i *UserInterface) SaveIdentity(ctx context.Context, identity *core.Identity) error {
	if identity.ID != "" {
		_, err := i.pool.Exec(ctx, 
			"UPDATE TABLE identities SET user_id = $1, type = $2, external_id = $3, issuer = $4 WHERE id = $5",
			identity.UserID, identity.Type, identity.ExternalID, identity.Issuer, identity.ID,
		)

		return err
	} 

	var id string
	err := i.pool.QueryRow(ctx, 
		"INSERT INTO TABLE identities(user_id, type, external_id, issuer) VALUES ($1, $2, $3, $4) RETURNING id",
		identity.UserID, identity.Type, identity.ExternalID, identity.Issuer,
	).Scan(&id)

	if err != nil {
		return err
	}

	identity.ID = id

	return nil
}

func (i *UserInterface) getHash(ctx context.Context, userID string) (string, error) {
	row := i.pool.QueryRow(ctx, 
		"SELECT hash FROM credentials WHERE user_id = $1",
		userID,
	)

	var hash string
	if err := row.Scan(&hash); err != nil {
		return "", err
	}

	return hash, nil
}

func (i *UserInterface) SavePassword(ctx context.Context, userID, rawPassword string) error {
	hashCost := 10
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(rawPassword), hashCost)	
	if err != nil {
		return err
	}

	_, err = i.pool.Exec(ctx, 
		"INSERT INTO credentials(user_id, hash) VALUES ($1, $2)",
		userID,
		hashedPassword,
	)

	return err
}

func (i *UserInterface) SaveCredential(ctx context.Context, credential *core.Credential) error {
	if credential.ID != "" { 
		_, err := i.pool.Exec(ctx, 
			"UPDATE TABLE credentials SET hash = $1, status = $2 WHERE id = $3",
			credential.Hash, credential.Status, credential.ID,
		)

		return err
	} 

	var id string
	var status string
	err := i.pool.QueryRow(ctx, 
		"INSERT INTO TABLE credentials(identity_id, type, hash) VALUES ($1, $2, $3) RETURNING id",
		credential.IdentityID, credential.Type, credential.Hash,
	).Scan(&id, &status)

	if err != nil {
		return err
	}

	credential.ID = id

	return nil
}
