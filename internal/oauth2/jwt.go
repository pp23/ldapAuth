package oauth2

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTPrivateClaims map[string]any

type JWTClaims struct {
	Data *JWTPrivateClaims `json:"d,omitempty"`
	*jwt.RegisteredClaims
}

// JWT claims with mapper function
func NewMappedJWTClaims(claims *JWTPrivateClaims, registeredClaims *jwt.RegisteredClaims) jwt.Claims {
	// TODO: Add user data like its role to the JWT
	// TODO: Add user data that the client requires and the resource owner granted to be read by the client
	return &JWTClaims{
		claims,
		registeredClaims,
	}
}

// JWT claims with mapper function and default registered claims
func NewMappedJWTClaimsWithDefaults(claims *JWTPrivateClaims) jwt.Claims {
	// TODO: Add user data like its role to the JWT
	// TODO: Add user data that the client requires and the resource owner granted to be read by the client
	return &JWTClaims{
		claims,
		&jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "",
			Subject:   "",
		},
	}
}
