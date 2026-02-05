package core

import (
	"context"
)

func GoogleOAuth(ctx context.Context, userInterface IUser, email, rawToken, provider, externalID, issuer string) (*User, error) {
	user, err := userInterface.ByIdentity(ctx, provider, externalID, issuer)	
	if err != nil {
		return nil, err
	}

	if user == nil {
		user, err = userInterface.ByEmail(ctx, email)	
		if err != nil {
			return nil, err
		}

		if user == nil {
			name := email	

			user, err = NewUser(name, email)
			if err != nil {
				return nil, err
			}

			err = userInterface.Create(ctx, user)
			if err != nil {
				return nil, err
			}
		} 

		identity, err := NewIdentity(provider, externalID, issuer)
		if err != nil {
			return nil, err
		}
		identity.UserID = user.ID

		credential, err := NewCredential("oauth", rawToken)
		if err != nil {
			return nil, err
		}

		err = userInterface.SaveIdentity(ctx, identity)
		if err != nil {
			return nil, err
		}
		credential.IdentityID = identity.ID

		err = userInterface.SaveCredential(ctx, credential)
		if err != nil {
			return nil, err
		}
	}

	return user, nil
}
