package http

import (
	"sso/internal/core"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"

	"errors"
	"net/http"
	"time"
)

func setSessionCookie(c echo.Context, token string, sessionExp int) {
	cookie := new(http.Cookie)
	cookie.Name = "sso_session_token"
	cookie.Value = token
	cookie.Path = "/"
	cookie.HttpOnly = true
	cookie.Secure = true
	cookie.SameSite = http.SameSiteLaxMode
	cookie.MaxAge = sessionExp
	cookie.Expires = time.Now().Add(time.Duration(sessionExp) * time.Second)

	c.SetCookie(cookie)
}

func loginHandler(loginUC *core.LoginUseCase, sessionExp int) echo.HandlerFunc {
	return func(c echo.Context) error {
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

		setSessionCookie(c, token, sessionExp)
		return c.NoContent(http.StatusOK)
	}
}

func registerHandler(registerUC *core.RegisterUseCase, sessionExp int) echo.HandlerFunc {
	return func(c echo.Context) error {
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

		setSessionCookie(c, token, sessionExp)
		return c.NoContent(http.StatusOK)
	}
}

func oauthHandler(oauthWorkflow *core.OAuthWorkflow) echo.HandlerFunc {
	return func(c echo.Context) error {
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

		redirectURI, err := oauthWorkflow.Execute(ctx, userID, request["client_id"], request["redirect_uri"])
		if err != nil {
			return err
		}

		return c.Redirect(http.StatusSeeOther, redirectURI)
	}
}

func jwksHandler(jwksUC *core.GetPublicKeysUseCase) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()

		keys, err := jwksUC.Execute(ctx)
		if err != nil {
			return err
		}

		return c.JSON(http.StatusOK, keys)
	}
}
