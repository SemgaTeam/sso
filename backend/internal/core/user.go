package core

import (
	"errors"
	"context"
)

type User struct {
	ID string `json:"id"`
	Name string `json:"name"`
	Email string `json:"email"`
	Status string `json:"status"`
	Identities []Identity
}

func NewUser(name, email string) (*User, error) {
	if name == "" || email == "" {
		return nil, errors.New("name and email must be not empty")
	}

	return &User{
		Name: name,
		Email: email,
		Status: "active",
	}, nil
}

func (u *User) CanLogin() bool {
	if u.Status == "deleted" || u.Status == "blocked" {
		return false
	}
	 
	return true
}

func (u *User) Update(name, email string) error {
	if u.Status == "deleted" {
		return errors.New("user is deleted")	
	}

	if name == "" || email == "" {
		return errors.New("name and email must be not empty")
	}

	u.Name = name
	u.Email = email

	return nil
}

func (u *User) Delete() error {
	if u.Status == "deleted" {
		return errors.New("user is already deleted")
	}

	u.Status = "deleted"

	return nil
}

type UserUseCase struct {
	user IUser
}

func NewUserUseCase(user IUser) *UserUseCase {
	return &UserUseCase{
		user,
	}
}

func (uc *UserUseCase) Get(ctx context.Context, id, name string) (*User, error) {
	var response *User

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

func (uc *UserUseCase) Create(ctx context.Context, name, email string) (*User, error) {
	user, err := NewUser(name, email)
	if err != nil {
		return nil, err
	}

	err = uc.user.Create(ctx, user)	
	if err != nil{
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
