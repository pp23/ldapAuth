package provider

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	const plaintext = "testplaintext"
	// secret needs to be 16 bytes for AES-128 or 32 bytes for AES-256
	cfg := `{
	"secret": {
	  "value": {
      "string": "12345678912345678912345678912345"
	  }
	}
	}`
	encProvider := EncryptionProvider{}
	err := json.Unmarshal([]byte(cfg), &encProvider)
	if err != nil {
		t.Errorf("ERROR: Could not unmarshal config `%s`: %v", cfg, err)
	}
	if encErr := encProvider.Open(); encErr != nil {
		t.Errorf("ERROR: Could not open encryptionProvider: %v", encErr)
	}
	defer encProvider.Close()
	ciphertext, encErr := encProvider.Encrypt([]byte(plaintext))
	t.Logf("Ciphertext: %x", ciphertext)
	if encErr != nil {
		t.Errorf("Encryption error: %v", encErr)
	}
	if pText, err := encProvider.Decrypt(ciphertext); err != nil {
		t.Errorf("Decryption error: %v", err)
	} else {
		if string(pText) != plaintext {
			t.Errorf("Expected plaintext %s, got %s. Hex: %x", plaintext, string(pText), pText)
		}
	}
}

// uses the same key and same encryptionProvider for multiple encryptions/decryptions
// expecting that no ciphertext is the same as the nonce must always change
func TestEncryptDecryptMultipleUsage(t *testing.T) {
	const plaintext = "testplaintext"
	// secret needs to be 16 bytes for AES-128 or 32 bytes for AES-256
	cfg := `{
	"secret": {
	  "value": {
      "string": "12345678912345678912345678912345"
	  }
	}
	}`
	var ciphertexts []string
	encProvider := EncryptionProvider{}
	err := json.Unmarshal([]byte(cfg), &encProvider)
	if err != nil {
		t.Errorf("ERROR: Could not unmarshal config `%s`: %v", cfg, err)
	}
	if encErr := encProvider.Open(); encErr != nil {
		t.Errorf("ERROR: Could not open encryptionProvider: %v", encErr)
	}
	defer encProvider.Close()
	for i := 0; i < 128; i++ {

		ciphertext, encErr := encProvider.Encrypt([]byte(plaintext))
		t.Logf("Ciphertext[%d]: %x", i, ciphertext)
		if encErr != nil {
			t.Errorf("Encryption error: %v", encErr)
		}
		ciphertexts = append(ciphertexts, fmt.Sprintf("%x", ciphertext))
	}
	for _, hexCiphertext := range ciphertexts {
		ct, err := hex.DecodeString(hexCiphertext)
		if err != nil {
			t.Errorf("Could not hex decode ciphertext %s: %v", hexCiphertext, err)
		}
		if pText, err := encProvider.Decrypt(ct); err != nil {
			t.Errorf("Decryption error: %v", err)
		} else {
			if string(pText) != plaintext {
				t.Errorf("Expected plaintext %s, got %s. Hex: %x", plaintext, string(pText), pText)
			}
		}
	}
}
