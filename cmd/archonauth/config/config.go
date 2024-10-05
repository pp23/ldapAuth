package config

import (
	"github.com/pp23/ldapAuth/internal/cache"
	"github.com/pp23/ldapAuth/internal/ldapIdp"
	"github.com/pp23/ldapAuth/internal/oauth2"
	"gopkg.in/yaml.v2"
)

// Config the plugin configuration.
type Config struct {
	Ldap    *ldapIdp.Config `json:"ldap,omitempty" yaml:"ldap,omitempty"`
	OAuth2  *oauth2.Config  `json:"oauth2,omitempty" yaml:"oauth2,omitempty"`
	Cache   *cache.Config   `json:"cache,omitempty" yaml:"cache,omitempty"`
	Port    uint16          `json:"port,omitempty" yaml:"port,omitempty"`
	Address string          `json:"address,omitempty" yaml:"address,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		Ldap:    ldapIdp.CreateConfig(),
		OAuth2:  oauth2.CreateConfig(),
		Cache:   cache.CreateConfig(),
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
