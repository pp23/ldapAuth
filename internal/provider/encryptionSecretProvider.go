package provider

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"slices"
	"strings"
)

// Provides encryption and its configuration

var supportedAlgorithms []string = []string{
	"AES-256",
	// TODO: Support more
}

type EncryptionProvider struct {
	Secret *ProviderSelector `json:"secret" yaml:"secret"`
	// aes mode with cipher block created out of Secret
	aesMode cipher.AEAD
	// nonce buffer. a nonce is only allowed to be used once per key!
	nonce []byte
	// AES-256 (TODO: Support more algorithms)
	Algorithm string `json:"algorithm,omitempty" yaml:"algorithm,omitempty"`
}

func (ep *EncryptionProvider) Open() error {
	if ep.Algorithm == "" {
		ep.Algorithm = "AES-256"
	}
	if !slices.Contains(supportedAlgorithms, ep.Algorithm) {
		return fmt.Errorf("Unsupported encryption algorithm %s. Available: %s", ep.Algorithm, strings.Join(supportedAlgorithms, ","))
	}
	if err := ep.Secret.Open(); err != nil {
		return err
	}
	key, err := ep.Read()
	if err != nil {
		return err
	}
	aesBlock, aesKeyErr := aes.NewCipher(key)
	if aesKeyErr != nil {
		return aesKeyErr
	}
	ep.nonce = make([]byte, 12)
	var aesModeErr error
	ep.aesMode, aesModeErr = cipher.NewGCM(aesBlock)
	if aesModeErr != nil {
		return aesModeErr
	}
	return nil
}

func (ep *EncryptionProvider) Read() ([]byte, error) {
	return ep.Secret.Read()
}

func (ep *EncryptionProvider) Close() error {
	return ep.Secret.Close()
}

// EncrptionProvider specific functions

// Encrypts the given plaintext according to the provided configuration paramaters. Returns an empty result on error. Prepends the used nonce to the ciphertext.
func (ep *EncryptionProvider) Encrypt(plaintext []byte) ([]byte, error) {
	// generate a new nonce. never use the same nonce with the same key!
	if _, err := io.ReadFull(rand.Reader, ep.nonce); err != nil {
		return []byte{}, err
	}
	// prepends nonce to the ciphertext
	return ep.aesMode.Seal(ep.nonce, ep.nonce, plaintext, nil), nil
}

// Decrypts the given ciphertext. Expects the nonce with current nonce buffer size length prepended to the ciphertext.
func (ep *EncryptionProvider) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < len(ep.nonce) {
		return []byte{}, fmt.Errorf("ERROR: Length of ciphertext %d is less than size of nonce buffer %d. Is the ciphertext valid and is the right nonce prepended to the ciphertext?", len(ciphertext), len(ep.nonce))
	}
	// read the prepended nonce
	ep.nonce = ciphertext[:len(ep.nonce)]
	return ep.aesMode.Open(nil, ep.nonce, ciphertext[len(ep.nonce):], nil)
}
