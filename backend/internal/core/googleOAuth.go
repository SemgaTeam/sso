package core

import (
	"go.uber.org/zap"

	"context"
)

func GoogleOAuth(ctx context.Context, userInterface IUser, email, rawToken, provider, externalID, issuer string) (*User, error) {
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

			user, err = NewUser(name, email)
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

		identity, err := NewIdentity(provider, externalID, issuer)
		if err != nil {
			log.Info("invalid identity", zap.Error(err))
			return nil, err
		}
		identity.UserID = user.ID

		credential, err := NewCredential("oauth", rawToken)
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
