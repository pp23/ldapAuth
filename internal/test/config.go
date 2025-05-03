package test

import (
	"fmt"
	"math/rand"
	"os"

	"github.com/pp23/ldapAuth/internal/config"
	"github.com/pp23/ldapAuth/internal/oauth2"
	"github.com/pp23/ldapAuth/internal/provider"
)

type TestConfig struct {
	TestUsername string
	TestPassword string
}

const (
	testUsernameEnvKey = "ARCHONAUTH_TEST_USERNAME"
	testPasswordEnvKey = "ARCHONAUTH_TEST_PASSWORD"
)

func TestConfigFromEnv() (TestConfig, error) {
	var cfg TestConfig
	if username, u_ok := os.LookupEnv(testUsernameEnvKey); u_ok {
		cfg.TestUsername = username
		if password, p_ok := os.LookupEnv(testPasswordEnvKey); p_ok {
			cfg.TestPassword = password
		} else {
			return cfg, fmt.Errorf("%s not set", testPasswordEnvKey)
		}
	} else {
		return cfg, fmt.Errorf("%s not set", testUsernameEnvKey)
	}
	return cfg, nil
}

func CreateConfig() *config.Config {
	cfg := config.CreateConfig()
	cfg.OAuth2.Clients = append(cfg.OAuth2.Clients, &oauth2.OAuth2Client{
		ClientId:    "abc",
		RedirectUri: "https://localhost:1234/token",
		ClientSecret: &provider.ProviderSelector{
			File: &provider.FileProvider{
				Path: "/tmp/testClientCredentials.txt",
			},
		},
	})
	return cfg
}

// Creates a Cache.Encryption provider with the given secret key (32byte for AES256). If key is empty, a random byte-array will be generated.
func CreateCacheEncryptionConfig(key []byte) *provider.EncryptionProvider {
	cacheEncKey := key
	if len(key) <= 0 {
		cacheEncKey = make([]byte, 32) // 32 bytes required for AES256
		rand.Read(cacheEncKey)
	}
	return &provider.EncryptionProvider{
		Secret: &provider.ProviderSelector{
			Value: &provider.ValueProvider{
				Value: string(cacheEncKey),
			},
		},
	}
}
