package jwt

import (
	"crypto/rsa"
	"errors"

	"github.com/golang-jwt/jwt"
)

var (
	ErrInvalidToken = errors.New("invalid token")
)

type Validator struct {
	publicKey *rsa.PublicKey
}

func NewValidator(pubKey *rsa.PublicKey) Validator {
	return Validator{publicKey: pubKey}
}

func (v Validator) Validate(tokenString string) (*jwt.Token, error) {
	t, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return v.publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	// Check if the token is valid
	if !t.Valid {
		return nil, ErrInvalidToken
	}

	return t, nil
}
