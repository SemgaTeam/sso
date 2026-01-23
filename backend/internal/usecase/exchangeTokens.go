package usecase

import (
	"github.com/SemgaTeam/sso/internal/domain"
	"github.com/SemgaTeam/sso/internal/entities"
	e "github.com/SemgaTeam/sso/internal/error"

	"time"
)

type ExchangeTokensUseCase struct {
	authCode domain.AuthCodeRepository
	token domain.TokenRepository
}

func NewExchangeTokensUseCase(authCodeRepo domain.AuthCodeRepository, tokenRepo domain.TokenRepository) *ExchangeTokensUseCase {
	return &ExchangeTokensUseCase{
		authCode: authCodeRepo,
		token: tokenRepo,
	}
}

func (uc *ExchangeTokensUseCase) Execute(code string) (accessToken, refreshToken *entities.Token, err error) {
	accessExpiration := time.Now().Add(time.Duration(3600*time.Second))
	refreshExpiration := time.Now().Add(time.Duration(7*24*3600*time.Second))

	authCode, err := uc.authCode.Get(code)
	if err != nil {
		return nil, nil, err
	}

	if authCode == nil {
		return nil, nil, e.AuthCodeNotFound
	}

	accessToken, err = domain.NewToken(authCode.UserID, authCode.ClientID, accessExpiration)
	if err != nil {
		return nil, nil, err
	}

  refreshToken, err = domain.NewToken(authCode.UserID, authCode.ClientID, refreshExpiration)
	if err != nil {
		return nil, nil, err
	}

	if err := uc.token.SaveAccess(accessToken); err != nil {
		return nil, nil, err
	}

	if err := uc.token.SaveRefresh(refreshToken); err != nil {
		return nil, nil, err
	}

	return
}
