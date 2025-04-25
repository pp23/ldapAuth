package oauth2

import (
	"encoding/gob"

	"github.com/pp23/ldapAuth/internal/provider"
	"github.com/pp23/ldapAuth/pkg/mapper"
)

// OAuth2 client struct
type OAuth2Client struct {
	ClientId     string                     `json:"client_id" yaml:"client_id"`
	RedirectUri  string                     `json:"redirect_uri" yaml:"redirect_uri"`
	ClientSecret *provider.ProviderSelector `json:"client_secret" yaml:"client_secret"`
	// client specific mappings. Allows to modify Key/Values from IdP before stored in JWT.
	IdpClaimMappers []*mapper.Mappings `json:"mappers,omitempty" yaml:"mappers,omitempty"`
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
	ConfigureGob()
	return &Config{
		Clients: []*OAuth2Client{},
	}
}

// Register OAuth2 structs in gob
func ConfigureGob() {
	gob.Register(AuthCode{})
	gob.Register(OpaqueToken{})
}
