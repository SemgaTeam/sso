package error

import (
	"errors"
	"fmt"
)

type DomainError struct {
	Err error `json:"-"`
}

func (e *DomainError) Error() string {
	return e.Err.Error()
}

func (e *DomainError) Unwrap() error {
	return e.Err
}

func NewDomainError(msg string) *DomainError {
	return &DomainError{
		Err: errors.New(msg),
	}
}

func Unknown(err error) *DomainError {
	return &DomainError{
		Err: fmt.Errorf("unknown error: %s", err.Error()),
	}
}

var (
	UserAlreadyExists = NewDomainError("user already exists")
	UserNotFound = NewDomainError("user not found")

	InvalidCredentials = NewDomainError("invalid credentials")
	EmptyPasswordIsNotPermitted = NewDomainError("empty password is not permitted")

	SigningMethodNotAllowed = NewDomainError("token signing method is not allowed")
	SigningTokenError = NewDomainError("error signing token")

	IdentityAlreadyExists = NewDomainError("identity already exists")
	CredentialAlreadyExists = NewDomainError("credential already exists")
)
