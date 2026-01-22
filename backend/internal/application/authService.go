package application

import (
	"github.com/SemgaTeam/sso/internal/domain"
	"github.com/SemgaTeam/sso/internal/dto"
	"github.com/SemgaTeam/sso/internal/entities"

	"strings"
)

type AuthResultType string

const (
	AuthorizationApproved        AuthResultType = "approved"
	AuthorizationConsentRequired AuthResultType = "consent_required"
	AuthorizationDenied          AuthResultType = "denied"
)

type AuthResult struct {
	Type AuthResultType
	Message string

	RedirectURI string

	Consent dto.ConsentView
}

type AuthService struct {
	authenticateUC AuthenticateUC
	registerUC RegisterUC
	consent domain.ConsentRepository
	client domain.ClientRepository
	authCode domain.AuthCodeRepository
}

func (s *AuthService) Execute(input domain.AuthInput) (*AuthResult, error) {
	authCodeTTL := uint(5*60) // 5 minutes

	var user *entities.User
	var err error
	switch input.Intent {
	case domain.IntentLogin:
		input := domain.AuthenticateInput{
			Email: input.Email,
			Password: input.Password,

			Provider: input.Provider,

			ExternalID: input.ExternalID,
			Token: input.Token,
			Issuer: input.Issuer,
		}

		user, err = s.authenticateUC.Execute(input)

	case domain.IntentRegister:
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
			Consent: dto.ConsentView{
				UserID: user.ID.String(),
				ClientID: client.ID.String(),
				ClientName: client.Name,
				Scopes: input.Scopes,
			},
		}, nil
	}

	scope := strings.Join(input.Scopes, " ")
	authCode, err := s.authCode.Issue(user.ID, client.ID, input.RedirectURI, scope, authCodeTTL)
	if err != nil {
		return nil, err
	}

	redirectURI := input.RedirectURI + "?code=" + authCode

	return &AuthResult{
		Type: AuthorizationApproved,
		RedirectURI: redirectURI,
	}, nil
}
