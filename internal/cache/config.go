package cache

import "github.com/pp23/ldapAuth/internal/provider"

type Config struct {
	Host string `json:"host,omitempty" yaml:"host,omitempty"`
	// Enables cache encryption if set
	Encryption *provider.EncryptionProvider `json:"encryption,omitempty" yaml:"encryption,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		Host: "localhost:11211",
	}
}
