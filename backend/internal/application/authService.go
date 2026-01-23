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

	ExchangeTokensSuccess        AuthResultType = "exchange tokens success"
	ExchangeTokensFailure        AuthResultType = "exchange tokens failure"
)

type AuthResult struct {
	Type AuthResultType
	Message string

	RedirectURI string

	Consent dto.ConsentView

	AccessToken string
	RefreshToken string
}

type AuthService struct {
	authenticateUC AuthenticateUC
	registerUC RegisterUC
	exchangeTokensUC ExchangeTokensUC
	consent domain.ConsentRepository
	client domain.ClientRepository
	authCode domain.AuthCodeRepository
}

func (s *AuthService) LogIn(input domain.AuthInput) (*AuthResult, error) {
	usecaseInput := domain.AuthenticateInput{
		Email: input.Email,
		Password: input.Password,

		Provider: input.Provider,

		ExternalID: input.ExternalID,
		Token: input.Token,
		Issuer: input.Issuer,
	}

	user, err := s.authenticateUC.Execute(usecaseInput)
	if err != nil{
		return nil, err
	}

	return s.continueOAuthWorkflow(user, input)
}

func (s *AuthService) Register(input domain.AuthInput) (*AuthResult, error) {
	usecaseInput := domain.RegisterInput{
		Name: input.Name,
		Email: input.Email,
		Password: input.Password,

		Provider: input.Provider,

		ExternalID: input.ExternalID,
		Token: input.Token,
		Issuer: input.Issuer,
	}

	user, err := s.registerUC.Execute(usecaseInput)
	if err != nil{
		return nil, err
	}

	return s.continueOAuthWorkflow(user, input)
}

func (s *AuthService) ExchangeTokens(authCode string) (*AuthResult, error) {
	access, refresh, err := s.exchangeTokensUC.Execute(authCode)	
	if err != nil {
		return &AuthResult{
			Type: ExchangeTokensFailure,
			Message: err.Error(),
		}, nil
	}

	return &AuthResult{
		Type: ExchangeTokensSuccess,
		AccessToken: access,
		RefreshToken: refresh,
	}, nil
}

func (s *AuthService) continueOAuthWorkflow(user *entities.User, input domain.AuthInput) (*AuthResult, error) {
	authCodeTTL := uint(5*60) // 5 minutes

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

	authCode, err := domain.NewAuthCode(
		user.ID,
		client.ID,
		input.RedirectURI,
		scope,
		authCodeTTL,
	)

	if err != nil {
		return nil, err
	}

	code, err := s.authCode.Save(authCode)
	if err != nil {
		return nil, err
	}

	redirectURI := input.RedirectURI + "?code=" + code

	return &AuthResult{
		Type: AuthorizationApproved,
		RedirectURI: redirectURI,
	}, nil
}
