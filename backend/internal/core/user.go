package core

import (
	e "sso/internal/core/entities"
	i "sso/internal/core/interfaces"

	"context"
)

type UserUseCase struct {
	user i.IUser
}

func NewUserUseCase(user i.IUser) *UserUseCase {
	return &UserUseCase{
		user,
	}
}

func (uc *UserUseCase) Get(ctx context.Context, id, name string) (*e.User, error) {
	var response *e.User

	if id != "" {
		user, err := uc.user.ByID(ctx, id)
		if err != nil {
			return nil, err
		}

		response = user
	} else if name != "" {
		user, err := uc.user.ByName(ctx, name)
		if err != nil {
			return nil, err
		}

		response = user
	}

	return response, nil
}

func (uc *UserUseCase) Create(ctx context.Context, name, email string) (*e.User, error) {
	user, err := e.NewUser(name, email)
	if err != nil {
		return nil, err
	}

	err = uc.user.Create(ctx, user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (uc *UserUseCase) Update(ctx context.Context, id, name, email string) error {
	user, err := uc.user.ByID(ctx, id)
	if err != nil {
		return err
	}

	if err := user.Update(name, email); err != nil {
		return err
	}

	err = uc.user.Update(ctx, user)
	return err
}

func (uc *UserUseCase) Delete(ctx context.Context, id string) error {
	user, err := uc.user.ByID(ctx, id)
	if err != nil {
		return err
	}

	if err := user.Delete(); err != nil {
		return err
	}

	err = uc.user.Update(ctx, user)
	return err
}
