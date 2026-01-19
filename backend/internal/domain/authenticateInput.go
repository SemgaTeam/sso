package domain

type AuthenticateInput struct {
	Email string       // \ local password authentication
	Password string    // /

	Provider string    // email or oauth

	ExternalID string  // \
	Token string       // |- oauth2 authentication
	Issuer string      // /
}
