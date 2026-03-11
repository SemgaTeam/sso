package core

import (
	"sso/internal/core/entities"
	i "sso/internal/core/interfaces"

	"go.uber.org/zap"

	"context"
)

func GoogleOAuth(ctx context.Context, userInterface i.IUser, email, rawToken, provider, externalID, issuer string) (*entities.User, error) {
	log := getLoggerFromContext(ctx)

	user, err := userInterface.ByIdentity(ctx, provider, externalID, issuer)
	if err != nil {
		log.Fatal("failed to get user by identity", zap.Error(err))
		return nil, err
	}

	if user == nil {
		user, err = userInterface.ByEmail(ctx, email)
		if err != nil {
			log.Fatal("failed to get user by email", zap.Error(err), zap.String("email", email))
			return nil, err
		}

		if user == nil {
			name := email

			user, err = entities.NewUser(name, email)
			if err != nil {
				log.Info("invalid user", zap.Error(err))
				return nil, err
			}

			err = userInterface.Create(ctx, user)
			if err != nil {
				log.Fatal("failed to create user", zap.Error(err))
				return nil, err
			}
		}

		identity, err := entities.NewIdentity(provider, externalID, issuer)
		if err != nil {
			log.Info("invalid identity", zap.Error(err))
			return nil, err
		}
		identity.UserID = user.ID

		credential, err := entities.NewCredential("oauth", rawToken)
		if err != nil {
			log.Info("invalid credential", zap.Error(err))
			return nil, err
		}

		err = userInterface.SaveIdentity(ctx, identity)
		if err != nil {
			log.Fatal("failed to save identity", zap.Error(err))
			return nil, err
		}
		credential.IdentityID = identity.ID

		err = userInterface.SaveCredential(ctx, credential)
		if err != nil {
			log.Fatal("failed to save credential", zap.Error(err))
			return nil, err
		}
	}

	return user, nil
}
