package infrastructure

import "golang.org/x/crypto/bcrypt"

type HashInterface struct {
	hashCost int 
}

func NewHashInterface(hashCost int) *HashInterface {
	return &HashInterface{
		hashCost,
	}
}

func (i *HashInterface) HashPassword(raw string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(raw), i.hashCost)	

	return string(hashedPassword), err
}

func (i *HashInterface) CheckPassword(raw, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(raw))		
}
