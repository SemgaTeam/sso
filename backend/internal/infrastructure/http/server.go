package http

import (
	"sso/internal/config"
	"sso/internal/core"
	e "sso/internal/core/errors"

	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/zap"

	"context"
	"errors"
	"fmt"
)

func SetupHandlers(conf *config.Config, e *echo.Echo, baseLogger *zap.Logger, userUC *core.UserUseCase, loginUC *core.LoginUseCase, registerUC *core.RegisterUseCase, oauthWorkflow *core.OAuthWorkflow, jwksUC *core.GetPublicKeysUseCase) {
	tokenMiddleware := echojwt.WithConfig(echojwt.Config{
		SigningKey:    []byte(conf.SigningKey),
		TokenLookup:   "cookie:sso_session_token",
		ContextKey:    "sso_session_token",
		SigningMethod: conf.SigningMethod.Alg(),
	})

	initMiddleware(e, baseLogger)

	auth := e.Group("/auth")
	auth.POST("/login", loginHandler(loginUC))
	auth.POST("/register", registerHandler(registerUC))
	auth.POST("/token", oauthHandler(oauthWorkflow), tokenMiddleware)
	auth.POST("/exchange", exchangeCodeHandler(oauthWorkflow))

	e.GET("/.well-known/jwks.json", jwksHandler(jwksUC))
}

func errorHandler(err error, c echo.Context) {
	var httpErr HTTPError
	var echoErr *echo.HTTPError

	switch {
	case errors.As(err, &httpErr):
		break
	case errors.As(err, &echoErr):
		httpErr.Code = echoErr.Code
		httpErr.Message = echoErr.Message.(string)

	case errors.Is(err, e.UserNotFound):
		httpErr = NotFound("user not found")

	case errors.Is(err, e.UserCannotBeLoggedIn):
		httpErr = BadRequest("user cannot be logged in")

	case errors.Is(err, e.UserCannotBeUpdated):
		httpErr = BadRequest("user cannot be updated")

	case errors.Is(err, e.RedirectURINotAllowed):
		httpErr = BadRequest("redirect uri is not allowed")

	case errors.Is(err, e.IdentityNotFound):
	case errors.Is(err, e.CredentialNotFound):
		httpErr = Unauthorized("authentication failure")

	case errors.Is(err, e.InvalidNameOrEmail):
		httpErr = BadRequest("invalid name or email")

	case errors.Is(err, e.ClientNotFound):
		httpErr = NotFound("client not found")

	case errors.Is(err, e.InvalidAuthProvider):
		httpErr = BadRequest("invalid authentication provider")

	default:
		httpErr = Internal("internal server error")
	}

	if !c.Response().Committed {
		c.JSON(httpErr.Code, map[string]string{
			"error": httpErr.Message,
		})
	}
}

func initMiddleware(e *echo.Echo, baseLogger *zap.Logger) {
	loggerMiddleware := func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			reqID := c.Response().Header().Get(echo.HeaderXRequestID)

			logger := baseLogger.With(zap.String("request_id", reqID))

			ctx := context.WithValue(c.Request().Context(), "requestId", reqID)
			ctx = context.WithValue(ctx, "logger", logger)

			c.SetRequest(c.Request().WithContext(ctx))

			return next(c)
		}
	}

	e.HTTPErrorHandler = errorHandler

	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogStatus:    true,
		LogURIPath:   true,
		LogMethod:    true,
		LogError:     true,
		LogRequestID: true,
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			fields := []zap.Field{zap.String("request_id", v.RequestID)}

			if v.Error != nil {
				fields = append(fields, zap.Error(v.Error))
			}

			baseLogger.Info(fmt.Sprintf("%v %v %v", v.Method, v.URIPath, v.Status), fields...)
			return nil
		},
	}))
	e.Use(middleware.RequestID())
	e.Use(loggerMiddleware)
}
