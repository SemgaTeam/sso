package infrastructure

import (
	"github.com/SemgaTeam/sso/internal/entities"
	e "github.com/SemgaTeam/sso/internal/error"
	"gorm.io/gorm"
	"github.com/google/uuid"

	"errors"
)

type UserRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{
		db,
	}
}

func (r *UserRepository) Save(user *entities.User) error {
	if err := r.db.Save(user).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return e.UserAlreadyExists
		} else {
			return e.Unknown(err)
		}
	}

	return nil
}

func (r *UserRepository) AddIdentity(identity *entities.Identity) error {
	if err := r.db.Save(identity).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return e.CredentialAlreadyExists
		} else {
			return e.Unknown(err)
		}
	}

	return nil
}

func (r *UserRepository) AddCredential(credential *entities.Credential) error {
	if err := r.db.Save(credential).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return e.IdentityAlreadyExists
		} else {
			return e.Unknown(err)
		}
	}

	return nil
}

func (r *UserRepository) ByID(id uuid.UUID) (*entities.User, error) {
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

func (r *UserRepository) ByEmail(email string) (*entities.User, error) {
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

func (r *UserRepository) ByIdentity(itype, external_id, issuer string) (*entities.User, error) {
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
