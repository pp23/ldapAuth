package provider

import (
	"fmt"
	"os"
)

// Provides the content of an environment variable

type EnvVarProvider struct {
	EnvKey string `json:"key" yaml:"key"`
}

func (evp *EnvVarProvider) Open() error {
	if _, ok := os.LookupEnv(evp.EnvKey); !ok {
		return fmt.Errorf("Environment variable with the name %s does not exist.", evp.EnvKey)
	}
	return nil
}

func (evp *EnvVarProvider) Read() ([]byte, error) {
	if value, ok := os.LookupEnv(evp.EnvKey); ok {
		return []byte(value), nil
	}
	return []byte{}, fmt.Errorf("Environment variable with the name %s does no longer exist.", evp.EnvKey)
}

func (evp *EnvVarProvider) Close() error {
	return nil
}
