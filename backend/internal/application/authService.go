package application

import (
	"github.com/SemgaTeam/sso/internal/domain"
	"github.com/SemgaTeam/sso/internal/entities"
	"github.com/google/uuid"

	"strings"
)

type AuthIntent string

const (
	IntentLogin    AuthIntent = "login"
	IntentRegister AuthIntent = "register"
)

type AuthInput struct {
	Intent AuthIntent	
	ClientID uuid.UUID
	Scopes []string
	RedirectURI string

	Name string
	Email string
	Password string

	Provider string

	ExternalID string
	Token string
	Issuer string
}

type AuthResultType string

const (
	AuthorizationApproved        AuthResultType = "approved"
	AuthorizationConsentRequired AuthResultType = "consent_required"
	AuthorizationDenied          AuthResultType = "denied"
)

type ConsentView struct {
	UserID uuid.UUID
	ClientID uuid.UUID
	ClientName string
	Scopes []string
}

type AuthResult struct {
	Type AuthResultType
	Message string

	RedirectURI string

	Consent ConsentView
}

type AuthService struct {
	authenticateUC AuthenticateUC
	registerUC RegisterUC
	consent domain.ConsentRepository
	client domain.ClientRepository
	authCode domain.AuthCodeRepository
}

func (s *AuthService) Execute(input AuthInput) (*AuthResult, error) {
	authCodeTTL := uint(5*60) // 5 minutes

	var user *entities.User
	var err error
	switch input.Intent {
	case IntentLogin:
		input := domain.AuthenticateInput{
			Email: input.Email,
			Password: input.Password,

			Provider: input.Provider,

			ExternalID: input.ExternalID,
			Token: input.Token,
			Issuer: input.Issuer,
		}

		user, err = s.authenticateUC.Execute(input)

	case IntentRegister:
		input := domain.RegisterInput{
			Name: input.Name,
			Email: input.Email,
			Password: input.Password,

			Provider: input.Provider,

			ExternalID: input.ExternalID,
			Token: input.Token,
			Issuer: input.Issuer,
		}

		user, err = s.registerUC.Execute(input)

	default:
		return &AuthResult{
			Type: AuthorizationDenied,
			Message: "invalid auth intent",
		}, nil
	}

	if err != nil {
		return nil, err
	}

	client, err := s.client.ByID(input.ClientID)
	if err != nil {
		return nil, err
	}

	if !domain.AllowsRedirect(client, input.RedirectURI) {
		return &AuthResult{
			Type: AuthorizationDenied,
			Message: "redirect_uri is not allowed for this client",
		}, nil
	}

	consented := s.consent.HasConsent(user.ID, client.ID, input.Scopes)
	if !consented {
		return &AuthResult{
			Type: AuthorizationConsentRequired,
			Consent: ConsentView{
				UserID: user.ID,
				ClientID: client.ID,
				ClientName: client.Name,
				Scopes: input.Scopes,
			},
		}, nil
	}

	scope := strings.Join(input.Scopes, " ")
	authCode, err := s.authCode.Issue(user.ID, client.ID, input.RedirectURI, scope, authCodeTTL)

	redirectURI := input.RedirectURI +
		"?code=" + authCode

	return &AuthResult{
		Type: AuthorizationApproved,
		RedirectURI: redirectURI,
	}, nil
}
