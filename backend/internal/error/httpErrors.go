package error

import (
	"fmt"
	"errors"
	"net/http"
)

type HTTPError struct {
	Code int `json:"code"`
	Message string `json:"message"`
	Err error `json:"-"`
}

func (e *HTTPError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *HTTPError) Unwrap() error {
	return e.Err
}

func BadRequest(err error, msg string) *HTTPError {
	return &HTTPError{
		Code: http.StatusBadRequest, 
		Message: msg, 
		Err: err,
	}
}

func Unauthorized(err error, msg string) *HTTPError {
	return &HTTPError{
		Code: http.StatusUnauthorized, 
		Message: msg, 
		Err: err,
	}
}

func Forbidden(err error, msg string) *HTTPError {
	return &HTTPError{
		Code: http.StatusForbidden, 
		Message: msg, 
		Err: err,
	}
}

func NotFound(err error, msg string) *HTTPError {
	return &HTTPError{
		Code: http.StatusNotFound, 
		Message: msg, 
		Err: err,
	}
}

func Internal(err error) *HTTPError {
	return &HTTPError{
		Code: http.StatusInternalServerError, 
		Message: "internal server error", 
		Err: err,
	}
}

func FromError(err error) *HTTPError {
	var transportError *HTTPError

	if errors.As(err, &transportError) {
		return transportError
	}

	return Internal(err)
}
