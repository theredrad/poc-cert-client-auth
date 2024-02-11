package web

import (
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt"
	jwtCore "github.com/theredrad/certauthz/core/jwt"
	"github.com/theredrad/certauthz/core/key"
)

const (
	authorizationHeader = "Authorization"
	tokenType           = "Bearer"
)

// JWTokenMiddleware is a middleware to validate the client JWT
type JWTokenMiddleware struct {
	validator jwtCore.Validator
}

// NewJWTokenMiddleware accepts the authority public key and returns a new instance of JWTokenMiddleware
func NewJWTokenMiddleware(publicKeyPath string) (*JWTokenMiddleware, error) {
	pubKey, err := key.ReadRSAPublicKeyFromDERFile(publicKeyPath)
	if err != nil {
		return nil, err
	}

	return &JWTokenMiddleware{
		validator: jwtCore.NewValidator(pubKey),
	}, nil
}

// Handle implements Middleware signature to validates request JWT
func (m *JWTokenMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenHeader := r.Header.Get(authorizationHeader)
		parsedHeader := strings.Split(tokenHeader, " ")
		if len(parsedHeader) != 2 || parsedHeader[0] != tokenType {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("invalid token"))
			return
		}

		token, err := m.validateClientToken(parsedHeader[1])
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(err.Error()))
			return
		}

		client := jwtCore.ClientFromToken(token)

		ctx := setClient(r.Context(), client)
		r = r.WithContext(ctx)
		next(w, r)
	}
}

// validateClientToken validates JWT
func (m *JWTokenMiddleware) validateClientToken(tokenString string) (*jwt.Token, error) {
	token, err := m.validator.Validate(tokenString)
	if err != nil {
		return nil, err
	}

	return token, nil
}
