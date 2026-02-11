package http

type HTTPError struct {
	Code int
	Message string
}

func NewError(code int, msg string) HTTPError {
	return HTTPError{
		Code: code,
		Message: msg,
	}
}

func NotFound(msg string) HTTPError {
	return HTTPError{
		Code: 404,
		Message: msg,
	}
}

func Forbidden(msg string) HTTPError {
	return HTTPError{
		Code: 403,
		Message: msg,
	}
}

func Unauthorized(msg string) HTTPError {
	return HTTPError{
		Code: 401,
		Message: msg,
	}
}

func BadRequest(msg string) HTTPError {
	return HTTPError{
		Code: 400,
		Message: msg,
	}
}

func Internal(msg string) HTTPError {
	return HTTPError{
		Code: 500,
		Message: msg,
	}
}
