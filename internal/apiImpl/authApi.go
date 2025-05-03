package archonauth

import (
	"bytes"
	"context"
	"encoding/gob"

	"github.com/bradfitz/gomemcache/memcache"
	"github.com/gorilla/sessions"

	"github.com/pp23/ldapAuth/internal/config"
	"github.com/pp23/ldapAuth/internal/utils"
)

// LdapAuth Struct plugin.
type LdapAuth struct {
	config *config.Config
}

type AuthAPI struct {
	Auth  *LdapAuth
	Log   *utils.Logger
	Cache *memcache.Client
	Store *sessions.CookieStore
}

// New created a new LdapAuth plugin.
func New(ctx context.Context, config *config.Config) (*LdapAuth, error) {
	// init cache encryption if set
	if config.Cache.Encryption != nil {
		if err := config.Cache.Encryption.Open(); err != nil {
			return nil, err
		}
	}
	return &LdapAuth{
		config: config,
	}, nil
}

// Closes all in the New() function initialized components.
// Calls the Close() functions of all despite an error, but collects all occurred errors.
func (ldapAuth *LdapAuth) Close() []error {
	var errs []error
	if ldapAuth.config.Cache.Encryption != nil {
		if e := ldapAuth.config.Cache.Encryption.Close(); e != nil {
			errs = append(errs, e)
		}
	}
	return errs
}

func encodeToBytes[T any](obj T) ([]byte, error) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(obj)
	return buf.Bytes(), err
}

func decodeFromBytes[T any](data []byte) (*T, error) {
	var buf bytes.Buffer
	var out T
	decoder := gob.NewDecoder(&buf)
	_, bufErr := buf.Write(data)
	if bufErr != nil {
		return nil, bufErr
	}
	gobErr := decoder.Decode(&out)
	if gobErr != nil {
		return nil, gobErr
	}
	return &out, nil
}
