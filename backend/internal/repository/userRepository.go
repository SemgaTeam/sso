package repository

import (
	"github.com/SemgaTeam/sso/internal/entities"
	e "github.com/SemgaTeam/sso/internal/error"
	"gorm.io/gorm"
	"github.com/google/uuid"

	"errors"
)

type UserRepository interface {
	ByID(uuid.UUID) (*entities.User, error)
	ByEmail(string) (*entities.User, error)
	ByIdentity(string, string, string) (*entities.User, error)

	RegisterUser(*entities.User, *entities.Identity, *entities.Credential) error // safely create user, identity and credential
}

type userRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) UserRepository {
	return &userRepository{
		db,
	}
}

func (r *userRepository) ByID(id uuid.UUID) (*entities.User, error) {
	var user entities.User
	if err := r.db.First(&user, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, e.UserNotFound
		} else {
			return nil, e.Unknown(err)
		}
	}

	return &user, nil
}

func (r *userRepository) ByEmail(email string) (*entities.User, error) {
	var user entities.User
	if err := r.db.First(&user, "email = ?", email).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, e.UserNotFound
		} else {
			return nil, e.Unknown(err)
		}
	}

	return &user, nil
}

func (r *userRepository) ByIdentity(itype, external_id, issuer string) (*entities.User, error) {
	var user entities.User
	if err := r.db.First(&user, "type = ? AND external_id = ? AND issuer = ?", itype, external_id, issuer).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, e.UserNotFound
		} else {
			return nil, e.Unknown(err)
		}
	}

	return &user, nil
}

func (r *userRepository) RegisterUser(
	user *entities.User, 
	identity *entities.Identity, 
	credential *entities.Credential,
) error {

	err := r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(user).Error; err != nil {
			if errors.Is(err, gorm.ErrDuplicatedKey) {
				return e.UserAlreadyExists
			} else {
				return e.Unknown(err)
			}
		}

		identity.UserID = user.ID

		if err := tx.Create(identity).Error; err != nil {
			if errors.Is(err, gorm.ErrDuplicatedKey) {
				return e.IdentityAlreadyExists
			} else {
				return e.Unknown(err)
			}
		}

		credential.IdentityID = identity.ID

		if err := r.db.Create(credential).Error; err != nil {
			if errors.Is(err, gorm.ErrDuplicatedKey) {
				return e.CredentialAlreadyExists
			} else {
				return e.Unknown(err)
			}
		}

		return nil
	})

	return err
}
