package config

import (
	"github.com/pp23/ldapAuth/internal/ldapIdp"
	"gopkg.in/yaml.v2"
)

// OAuth2 config
type OAuth2 struct {
	RedirectURI string `json:"redirect_uri" yaml:"redirect_uri"`
}

// Config the plugin configuration.
type Config struct {
	Ldap    *ldapIdp.Config `json:"ldap,omitempty" yaml:"ldap,omitempty"`
	OAuth2  *OAuth2         `json:"oauth2,omitempty" yaml:"oauth2,omitempty"`
	Port    uint16          `json:"port,omitempty" yaml:"port,omitempty"`
	Address string          `json:"address,omitempty" yaml:"address,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		Ldap:    ldapIdp.CreateConfig(),
		Port:    3000,
		Address: "0.0.0.0",
	}
}

func (cfg *Config) FromYaml(data []byte) (*Config, error) {
	err := yaml.Unmarshal(data, cfg)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}
