package provider

import (
	"encoding/json"
	"os"
	"testing"
)

func TestEnvVarProvider(t *testing.T) {
	const (
		expectedKey   = "TEST_ENV_KEY"
		expectedValue = "TEST_ENV_VALUE"
	)

	if err := os.Setenv(expectedKey, expectedValue); err != nil {
		t.Errorf("Could not set test environmen variable with key %s and value %s: %v", expectedKey, expectedValue, err)
	}

	if value, ok := os.LookupEnv(expectedKey); !ok {
		t.Errorf("Could not set test environment variable")
	} else {
		if value != expectedValue {
			t.Errorf("Test environment variable has not the set expected value")
		}
	}
	cfg := `{
	"key": "` + expectedKey + `"
	}`

	var p EnvVarProvider

	if err := json.Unmarshal([]byte(cfg), &p); err != nil {
		t.Errorf("Could not parse config %s: %v", cfg, err)
	}
	if err := p.Open(); err != nil {
		t.Errorf("Could not open provider: %v; Config: %s", err, cfg)
	}
	value, err := p.Read()
	if err != nil {
		t.Errorf("Could not read environment variable: %v; Config: %s", err, cfg)
	}
	if string(value) != expectedValue {
		t.Errorf("Expected value %s, got %s with environment key %s", expectedValue, value, expectedKey)
	}
	if err := p.Close(); err != nil {
		t.Errorf("Could not close provider: %v", err)
	}
}
