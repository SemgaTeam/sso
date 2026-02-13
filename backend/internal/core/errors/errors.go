package errors

import (
	"errors"
)

type Error error

func NewError(msg string) Error {
	return errors.New(msg)
}

func Unknown(err error) Error {
	return errors.New("unkown error: " + err.Error())
}

var (
	UserNotFound = NewError("user not found")
	UserCannotBeLoggedIn = NewError("user cannot be logged in")
	UserCannotBeUpdated = NewError("user cannot be updated")
	InvalidNameOrEmail = NewError("user name or email is invalid")

	ClientNotFound = NewError("client not found")
	RedirectURINotAllowed = NewError("redirect uri not allowed")

	IdentityNotFound = NewError("identity not found")

	CredentialNotFound = NewError("credential not found")

	KeyIsNil = NewError("private key is nil")
	KeysNotFound = NewError("keys not found")

	UniqueViolated = NewError("unique constraint violated")

	InvalidAuthProvider = NewError("invalid authentication provider")
)
