package infrastructure

import (
	"sso/internal/core"
	e "sso/internal/core/errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"context"
	"errors"
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
	"SELECT name, email, status FROM users WHERE id = $1",
		id,
	).Scan(&name, &email, &status)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		} else {
			return nil, e.Unknown(err)
		}
	}

	user := core.User{
		ID: id,
		Name: name,
		Email: email,
		Status: status,
	}

	if err := i.preload(ctx, &user); err != nil {
		return nil, err
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
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		} else {
			return nil, e.Unknown(err)
		}
	}

	user := core.User{
		ID: id,
		Name: name,
		Email: email,
		Status: status,
	}

	if err := i.preload(ctx, &user); err != nil {
		return nil, err
	}

	return &user, nil
}

func (i *UserInterface) ByEmail(ctx context.Context, email string) (*core.User, error) {
	var id string
	var name string
	var status string

	err := i.pool.QueryRow(ctx,
		"SELECT id, name, status FROM users WHERE email = $1",
		email,
	).Scan(&id, &name, &status)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		} else {
			return nil, e.Unknown(err)
		}
	}

	user := core.User{
		ID: id,
		Name: name,
		Email: email,
		Status: status,
	}

	if err := i.preload(ctx, &user); err != nil {
		return nil, err
	}

	return &user, nil
}

func (i *UserInterface) ByName(ctx context.Context, name string) (*core.User, error) {
	var id string
	var email string
	var status string

	err := i.pool.QueryRow(ctx, 
	"SELECT id, email, status FROM users WHERE name = $1",
		name,
	).Scan(&id, &email, &status)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		} else {
			return nil, e.Unknown(err)
		}
	}

	user := core.User{
		ID: id,
		Name: name,
		Email: email,
		Status: status,
	}

	if err := i.preload(ctx, &user); err != nil {
		return nil, err
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
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique violation
			return e.UniqueViolated
		} else {
			return e.Unknown(err)
		}
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

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique violation
			return e.UniqueViolated
		} else {
			return e.Unknown(err)
		}
	}

	return nil
}

func (i *UserInterface) SaveIdentity(ctx context.Context, identity *core.Identity) error {
	if identity.ID != "" {
		_, err := i.pool.Exec(ctx, 
			"UPDATE identities SET user_id = $1, type = $2, external_id = $3, issuer = $4 WHERE id = $5",
			identity.UserID, identity.Type, identity.ExternalID, identity.Issuer, identity.ID,
		)

		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23503" { // foreign key violation
				return e.UserNotFound
			} else {
				return e.Unknown(err)
			}
		}

		return nil
	} 

	var id string
	err := i.pool.QueryRow(ctx, 
		"INSERT INTO identities(user_id, type, external_id, issuer) VALUES ($1, $2, $3, $4) RETURNING id",
		identity.UserID, identity.Type, identity.ExternalID, identity.Issuer,
	).Scan(&id)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" { // foreign key violation
			return e.UserNotFound
		} else {
			return e.Unknown(err)
		}
	}

	identity.ID = id

	return nil
}

func (i *UserInterface) SaveCredential(ctx context.Context, credential *core.Credential) error {
	if credential.ID != "" { 
		_, err := i.pool.Exec(ctx, 
			"UPDATE credentials SET hash = $1, status = $2 WHERE id = $3",
			credential.Hash, credential.Status, credential.ID,
		)

		return err
	} 

	var id string
	err := i.pool.QueryRow(ctx, 
		"INSERT INTO credentials(identity_id, type, hash) VALUES ($1, $2, $3) RETURNING id",
		credential.IdentityID, credential.Type, credential.Hash,
	).Scan(&id)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" { // foreign key violation
			return e.IdentityNotFound
		} else {
			return e.Unknown(err)
		}
	}

	credential.ID = id

	return nil
}

func (i *UserInterface) preload(ctx context.Context, user *core.User) error {
	identityRows, err := i.pool.Query(ctx, 
		"SELECT id, type, external_id, issuer, created_at FROM identities WHERE user_id = $1",
		user.ID,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		} else {
			return e.Unknown(err)
		}
	}
	defer identityRows.Close()

	for identityRows.Next() {
		var identity core.Identity

		err := identityRows.Scan(&identity.ID, &identity.Type, &identity.ExternalID, &identity.Issuer, &identity.CreatedAt)

		if err != nil {
			return e.Unknown(err)
		}

		credentialRows, err := i.pool.Query(ctx, 
			"SELECT id, type, hash, status, created_at FROM credentials WHERE identity_id = $1",
			identity.ID,
		)

		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			} else {
				return e.Unknown(err)
			}
		}
		defer credentialRows.Close()

		for credentialRows.Next() {
			var cred core.Credential

			err := credentialRows.Scan(&cred.ID, &cred.Type, &cred.Hash, &cred.Status, &cred.CreatedAt)

			if err != nil {
				return e.Unknown(err)
			}

			identity.Credentials = append(identity.Credentials, cred)
		}

		user.Identities = append(user.Identities, identity)
	}

	return nil
}
