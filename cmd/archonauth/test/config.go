package test

import (
	"fmt"
	"os"
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
