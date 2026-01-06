package error

import (
	"errors"
)

func MapDomainToHTTP(err *DomainError) *HTTPError {
	switch {
	case errors.Is(err, UserAlreadyExists):
		return BadRequest(err, "user already exists")

	case errors.Is(err, UserNotFound):
		return NotFound(err, "user not found")

	case errors.Is(err, InvalidCredentials):
		return Unauthorized(err, "invalid credentials")

	default:
		return Internal(err)	
	}
}
