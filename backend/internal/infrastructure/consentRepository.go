package infrastructure

import (
	"github.com/SemgaTeam/sso/internal/entities"
	e "github.com/SemgaTeam/sso/internal/error"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type ConsentRepository struct {
	db *gorm.DB
}

func NewConsentRepository(db *gorm.DB) *ConsentRepository {
	return &ConsentRepository{
		db,
	}
}

func (r *ConsentRepository) Save(userID, clientID uuid.UUID, scopes []string) error {
	consent := entities.Consent{
		UserID: userID,
		ClientID: clientID,
		Scopes: scopes,
	}

	if err := r.db.Save(&consent).Error; err != nil {
		return e.Unknown(err)
	}

	return nil
}

func (r *ConsentRepository) HasConsent(userID, clientID uuid.UUID, scopes []string) bool {
	var consent entities.Consent

	err := r.db.Where("user_id = ? AND client_id = ?", userID, clientID).Take(&consent).Error
	if err != nil {
		return false
	}

	subset := true
	for _, inputScope := range scopes {
		inScopes := false
		for	_, scope := range consent.Scopes {
			if inputScope == scope {
				inScopes = true
			}	
		} 

		if !inScopes {
			subset = false
			break
		}
	}

	return subset
}

func (r *ConsentRepository) ClientScopes(clientID uuid.UUID) ([]string, error) {
	var clientScopes []entities.ClientScope

	err := r.db.
		Where("client_id = ?", clientID).
		Preload("Scope").
		Find(&clientScopes).
		Error

	if err != nil {
		return nil, e.Unknown(err)
	}

	var scopeNames []string

	for _, cs := range clientScopes {
		scopeNames = append(scopeNames, cs.Scope.Name)
	}

	return scopeNames, nil
}
