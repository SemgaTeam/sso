package http

import (
	"sso/internal/core"
	e "sso/internal/core/errors"

	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/zap"

	"context"
	"errors"
	"net/http"
	"fmt"
)

func SetupHandlers(e *echo.Echo, baseLogger *zap.Logger, userUC *core.UserUseCase, loginUC *core.LoginUseCase, registerUC *core.RegisterUseCase, oauthWorkflow *core.OAuthWorkflow, jwksUC *core.GetPublicKeysUseCase) {
	tokenMiddleware := echojwt.WithConfig(echojwt.Config{
		SigningKey: []byte("secret"),
		TokenLookup: "cookie:sso_session_token",
		ContextKey: "sso_session_token",
		SigningMethod: jwt.SigningMethodHS256.Alg(),
	})

	loggerMiddleware := func(next echo.HandlerFunc) echo.HandlerFunc {
		return func (c echo.Context) error {
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
		LogStatus: true,
		LogURIPath: true,
		LogMethod: true,
		LogError: true,
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

	auth := e.Group("/auth")

	auth.POST("/login", func(c echo.Context) error {
		ctx := c.Request().Context()
		params := c.QueryParams()

		if params["provider"] == nil {
			return errors.New("provider query parameter is not specified")
		}
		if len(params["provider"]) > 1 {
			return errors.New("provider query parameter must be of length 1")
		}

		provider := params["provider"][0]
		var input core.LoginInput

		switch provider {
		case "email":
			request := map[string]string{
				"email": "",
				"password": "",
			}
			if err := c.Bind(&request); err != nil {
				return err
			}
			
			input = core.LoginInput{
				Provider: "email",
				Email: request["email"],
				Password: request["password"],
			}
		case "oauth":
			idToken := c.Get("id_token").(map[string]string)

			input = core.LoginInput{
				Provider: "oauth",
				
				Issuer: idToken["issuer"],
				ExternalID: idToken["sub"],
				Token: idToken,
			}
		}

		token, err := loginUC.Execute(ctx, input)
		if err != nil {
			return err
		}

		return c.JSON(http.StatusOK, map[string]any{
			"sso_session_token": token,
		})
	})

	auth.POST("/register", func(c echo.Context) error {
		ctx := c.Request().Context()
		params := c.QueryParams()

		if params["provider"] == nil {
			return errors.New("provider query parameter is not specified")
		}
		if len(params["provider"]) > 1 {
			return errors.New("provider query parameter must be of length 1")
		}

		provider := params["provider"][0]
		var input core.RegisterInput

		switch provider {
		case "email":
			request := map[string]string{
				"name": "",
				"email": "",
				"password": "",
			}

			if err := c.Bind(&request); err != nil {
				return err
			}

			input = core.RegisterInput{
				Provider: "email",
				Name: request["name"],
				Email: request["email"],
				Password: request["password"],
			}

		case "oauth":
			idToken := c.Get("id_token").(map[string]string)

			input = core.RegisterInput{
				Provider: "oauth",
				
				Issuer: idToken["issuer"],
				ExternalID: idToken["sub"],
				Token: idToken,
			}
		}

		token, err := registerUC.Execute(ctx, input)
		if err != nil {
			return err
		}

		return c.JSON(http.StatusOK, map[string]any{
			"sso_session_token": token,
		})
	})

	auth.POST("/token", func(c echo.Context) error {
		ctx := c.Request().Context()

		request := map[string]string{
			"client_id": "",
			"redirect_uri": "",
		}

		if err := c.Bind(&request); err != nil {
			return err
		}

		token, ok := c.Get("sso_session_token").(*jwt.Token)
		if !ok {
			return c.JSON(http.StatusUnauthorized, map[string]any{
				"error": "unauthorized",
			})
		}

		userID, err := token.Claims.GetSubject()
		if err != nil {
			return err
		}

		accessToken, refreshToken, err := oauthWorkflow.Execute(ctx, userID, request["client_id"], request["redirect_uri"])
		if err != nil {
			return err
		}

		return c.JSON(http.StatusOK, map[string]any{
			"access_token": accessToken,
			"refresh_token": refreshToken,
		})

	}, tokenMiddleware)

	e.GET("/.well-known/jwks.json", func(c echo.Context) error {
		keys, err := jwksUC.Execute()
		if err != nil {
			return err
		}

		return c.JSON(http.StatusOK, keys)
	})
}

func errorHandler(err error, c echo.Context) {
	var httpErr HTTPError
	var echoErr *echo.HTTPError

	switch {
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
