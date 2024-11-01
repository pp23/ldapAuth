package oauth2

import (
	"github.com/pp23/ldapAuth/internal/provider"
)

// OAuth2 client struct
type OAuth2Client struct {
	ClientId     string                     `json:"client_id" yaml:"client_id"`
	RedirectUri  string                     `json:"redirect_uri" yaml:"redirect_uri"`
	ClientSecret *provider.ProviderSelector `json:"client_secret" yaml:"client_secret"`
}

// OAuth2 config
type Config struct {
	Clients []*OAuth2Client `json:"clients" yaml:"clients"`
	// Scope            []string          `json:"scope,omitempty" yaml:"scope,omitempty"`
	// JWTSigningSecret string            `json:"jwt_signing_secret" yaml:"jwt_signing_secret"`
	// JWTExpiration    uint64            `json:"jwt_expiration_seconds,omitempty" yaml:"jwt_expiration_seconds,omitempty"`
	// JWTClaims        map[string]string `json:"jwt_claims,omitempty" yaml:"jwt_claims,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		Clients: []*OAuth2Client{},
	}
}
