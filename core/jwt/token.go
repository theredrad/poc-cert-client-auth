package jwt

import (
	"github.com/golang-jwt/jwt"

	"github.com/theredrad/certauthz/core/common"
)

// ClientFromToken returns the client from the jwt token
func ClientFromToken(token *jwt.Token) common.Client {
	client := common.Client{
		Scopes: make(common.Scopes),
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return client
	}

	tokenScopes, ok := claims["scopes"].([]any)
	if !ok {
		return client
	}

	name, _ := claims["sub"].(string)
	client.Name = name

	for _, s := range tokenScopes {
		client.Scopes[s.(string)] = struct{}{}
	}

	return client
}
