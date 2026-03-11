package entities

import (
	e "sso/internal/core/errors"
)

type User struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Email      string `json:"email"`
	Status     string `json:"status"`
	Identities []Identity
}

func NewUser(name, email string) (*User, error) {
	if name == "" || email == "" {
		return nil, e.InvalidNameOrEmail
	}

	return &User{
		Name:   name,
		Email:  email,
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
		return e.UserCannotBeUpdated
	}

	if name == "" || email == "" {
		return e.InvalidNameOrEmail
	}

	u.Name = name
	u.Email = email

	return nil
}

func (u *User) Delete() error {
	if u.Status == "deleted" {
		return nil
	}

	u.Status = "deleted"

	return nil
}
