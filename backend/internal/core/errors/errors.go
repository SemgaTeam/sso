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
	ClientNotFound = NewError("client not found")

	KeyIsNil = NewError("private key is nil")
)
