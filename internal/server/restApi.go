package server

import (
	"crypto/rand"
	"encoding/gob"

	"github.com/bradfitz/gomemcache/memcache"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/sessions"
	"github.com/pp23/ldapAuth/internal/api"
	archonauth "github.com/pp23/ldapAuth/internal/apiImpl"
	"github.com/pp23/ldapAuth/internal/config"
	"github.com/pp23/ldapAuth/internal/oauth2"
	"github.com/pp23/ldapAuth/internal/utils"
)

// TODO: Setup CSRF protection. See https://gist.github.com/ansrivas/4604d16a6f4d88eee657659d458080bc
// and https://owasp.org/www-community/attacks/csrf

// TODO: make idp more abstract to allow other IdPs than a LDAP
func NewAuthApi(idp *archonauth.LdapAuth, logger *utils.Logger, config *config.Config) (*archonauth.AuthAPI, error) {
	var store *sessions.CookieStore
	// Create new session with CacheKey and CacheTimeout.
	// TODO: dynamically generated rand number could cause decryption errors
	// when a new instance gets created with a new key
	encKey := make([]byte, 32) // 32 byte key -> AES-256 mode
	_, err := rand.Read(encKey)
	if err != nil {
		return nil, err
	}

	gob.Register(oauth2.AuthCode{})
	gob.Register(oauth2.OpaqueToken{})
	store = sessions.NewCookieStore([]byte(config.Ldap.CacheKey), encKey)
	store.Options = &sessions.Options{
		HttpOnly: true,
		MaxAge:   int(config.Ldap.CacheTimeout),
		Path:     config.Ldap.CacheCookiePath,
		Secure:   config.Ldap.CacheCookieSecure,
	}
	return &archonauth.AuthAPI{
		Auth:  idp,
		Log:   logger,
		Cache: memcache.New(config.Cache.Host),
		Store: store,
	}, nil
}

func NewChiRouter(apiImpl api.ServerInterface) chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Mount("/", api.HandlerWithOptions(apiImpl, api.ChiServerOptions{}))
	return r
}
