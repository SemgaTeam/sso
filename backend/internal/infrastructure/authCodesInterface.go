package infrastructure

import (
	"github.com/google/uuid"

	"slices"
	"time"
)

type AuthCodesInterface struct {
	codes []AuthCode
}

type AuthCode struct {
	raw string
	clientID string
	redirectURI string
	userID string
	expiration time.Time
}

func NewAuthCodesInterface() *AuthCodesInterface {
	return &AuthCodesInterface{
		codes: []AuthCode{},
	}
}

func (i *AuthCodesInterface) Issue(clientID, redirectURI, userID string, ttl int) (string, error) {
	exp := time.Now().Add(time.Duration(ttl)*time.Second)

	authCode := AuthCode{
		raw: uuid.New().String(),
		clientID: clientID,
		redirectURI: redirectURI,
		userID: userID,
		expiration: exp,
	}

	i.codes = append(i.codes, authCode)

	return authCode.raw, nil
}

func (i *AuthCodesInterface) Get(code string) (string, string, string, error) {
	var authCode *AuthCode
	for _, c := range i.codes {
		if c.raw == code && c.expiration.After(time.Now()) {
			authCode = &c
			break
		}
	}

	if authCode == nil {
		return "", "", "", nil
	}

	return authCode.clientID, authCode.redirectURI, authCode.userID, nil
}

func (i *AuthCodesInterface) Delete(code string) error {
	var authCode *AuthCode
	for _, c := range i.codes {
		if c.raw == code {
			authCode = &c
		}
	}

	if authCode != nil {
		i.codes = slices.DeleteFunc(i.codes, func(c AuthCode) bool {
			return c.raw == code
		})
	}

	return nil
}
