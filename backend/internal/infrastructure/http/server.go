package http

import (
	"sso/internal/core"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"

	"net/http"
	"errors"
)

func SetupHandlers(e *echo.Echo, pool *pgxpool.Pool, userUC *core.UserUseCase, loginUC *core.LoginUseCase, registerUC *core.RegisterUseCase, oauthWorkflow *core.OAuthWorkflow) {
	auth := e.Group("/auth")

	tokenMiddleware := echojwt.WithConfig(echojwt.Config{
		SigningKey: []byte("secret"),
		TokenLookup: "cookie:sso_session_token",
		ContextKey: "sso_session_token",
		SigningMethod: jwt.SigningMethodHS256.Alg(),
	})

	e.HTTPErrorHandler = errorHandler

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
}

func errorHandler(err error, c echo.Context) {
	if !c.Response().Committed {
		c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}
}
