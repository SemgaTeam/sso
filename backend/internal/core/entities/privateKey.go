package entities

import "crypto/rsa"

type PrivateKey struct {
	Value rsa.PrivateKey
	Name  string
}
