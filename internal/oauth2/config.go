package oauth2

type Config struct {
	ClientId         string            `json:"client_id,omitempty" yaml:"client_id,omitempty"`
	Scope            []string          `json:"scope,omitempty" yaml:"scope,omitempty"`
	JWTSigningSecret string            `json:"jwt_signing_secret" yaml:"jwt_signing_secret"`
	JWTExpiration    uint64            `json:"jwt_expiration_seconds,omitempty" yaml:"jwt_expiration_seconds,omitempty"`
	JWTClaims        map[string]string `json:"jwt_claims,omitempty" yaml:"jwt_claims,omitempty"`
}

func CreateConfig() *Config {
	return &Config{}
}
