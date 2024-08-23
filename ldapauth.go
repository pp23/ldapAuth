// Package ldapAuth a ldap authentication plugin.
// nolint
package ldapAuth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/sessions"
	"github.com/pp23/ldapAuth/internal/ldapIdp"
	"github.com/pp23/ldapAuth/internal/oauth2"
)

// nolint
var (
	store *sessions.CookieStore
	// LoggerDEBUG level.
	LoggerDEBUG = log.New(ioutil.Discard, "DEBUG: ldapAuth: ", log.Ldate|log.Ltime|log.Lshortfile)
	// LoggerINFO level.
	LoggerINFO = log.New(ioutil.Discard, "INFO: ldapAuth: ", log.Ldate|log.Ltime|log.Lshortfile)
	// LoggerERROR level.
	LoggerERROR = log.New(ioutil.Discard, "ERROR: ldapAuth: ", log.Ldate|log.Ltime|log.Lshortfile)
)

// LdapAuth Struct plugin.
type LdapAuth struct {
	next       http.Handler
	name       string
	config     *ldapIdp.Config
	cache      *memcache.Client
	gobEncoder *gob.Encoder
	gobDecoder *gob.Decoder
	gobByteBuf *bytes.Buffer
}

// Config the plugin configuration.
type Config struct {
	Ldap *ldapIdp.Config `json:"ldap" yaml:"ldap"`
}

func CreateConfig() *Config {
	return &Config{
		Ldap: ldapIdp.CreateConfig(),
	}
}

// New created a new LdapAuth plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	SetLogger(config.Ldap.LogLevel)

	LoggerINFO.Printf("Starting %s Middleware...", name)

	LogConfigParams(config)

	// Create new session with CacheKey and CacheTimeout.
	// TODO: dynamically generated rand number could cause decryption errors
	// when a new instance gets created with a new key
	encKey := make([]byte, 32) // 32 byte key -> AES-256 mode
	_, err := rand.Read(encKey)
	if err != nil {
		return nil, err
	}
	store = sessions.NewCookieStore([]byte(config.Ldap.CacheKey), encKey)
	store.Options = &sessions.Options{
		HttpOnly: true,
		MaxAge:   int(config.Ldap.CacheTimeout),
		Path:     config.Ldap.CacheCookiePath,
		Secure:   config.Ldap.CacheCookieSecure,
	}

	gob.Register(oauth2.AuthCode{})
	gob.Register(oauth2.OpaqueToken{})
	var buf bytes.Buffer

	return &LdapAuth{
		name:       name,
		next:       next,
		config:     config.Ldap,
		cache:      memcache.New("127.0.0.1:11211"), // TODO: make it configurable
		gobEncoder: gob.NewEncoder(&buf),
		gobDecoder: gob.NewDecoder(&buf),
		gobByteBuf: &buf,
	}, nil
}

func (la *LdapAuth) encodeToBytes(obj interface{}) ([]byte, error) {
	la.gobByteBuf.Reset()
	err := la.gobEncoder.Encode(obj)
	return la.gobByteBuf.Bytes(), err
}

func (la *LdapAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if !la.config.Enabled {
		LoggerINFO.Printf("%s Disabled! Passing request...", la.name)
		la.next.ServeHTTP(rw, req)
		return
	}

	var err error

	// #### JWT ####
	// opaque token sent from client, replace it with a JWT
	if authValue, ok := req.Header["Authorization"]; ok {
		if len(strings.Fields(authValue[0])) == 2 && strings.Fields(authValue[0])[0] == "Bearer" {
			opaqueToken := strings.Fields(authValue[0])[1]
			// do we have a session with this opaqueToken?
			item, cacheErr := la.cache.Get(opaqueToken)
			if cacheErr != nil {
				log.Printf("JWT: opaqueToken not found in cache: %v", cacheErr)
				RequireAuth(rw, req, la.config, cacheErr)
				return
			}
			// TODO: validate JWT token which were set by us anyway?
			req.Header["Authorization"] = []string{"Bearer " + string(item.Value)}
			la.next.ServeHTTP(rw, req)
			return
		}
	}
	// ########

	// #### Token ####
	// opaque token requested?
	if oauth2.IsOpaqueTokenRequest(req) {
		opaqueTokenRequest, err := oauth2.OpaqueTokenFromRequest(req)
		if err != nil {
			log.Printf("opaque token error: %v", err)
			RequireAuth(rw, req, la.config, err)
			return
		}
		var authCodeRequest oauth2.AuthCode
		la.gobByteBuf.Reset()
		item, cacheErr := la.cache.Get("code" + opaqueTokenRequest.Code)
		if cacheErr != nil {
			log.Printf("opaqueTokenRequest cache error: %v", cacheErr)
			RequireAuth(rw, req, la.config, cacheErr)
			return
		}
		_, bufErr := la.gobByteBuf.Write(item.Value)
		if bufErr != nil {
			log.Printf("opaqueTokenRequest decoding buffer error: %v", bufErr)
			RequireAuth(rw, req, la.config, bufErr)
			return
		}
		gobErr := la.gobDecoder.Decode(&authCodeRequest)
		if gobErr != nil {
			log.Printf("opaqueTokenRequest decoding error: %v", gobErr)
			RequireAuth(rw, req, la.config, gobErr)
			return
		}
		accessToken, err := opaqueTokenRequest.AccessToken(600)
		if err != nil {
			log.Printf("opaque token error: %v", err)
			RequireAuth(rw, req, la.config, err)
			return
		}
		jsonAT, errJson := accessToken.Json()
		if errJson != nil {
			log.Printf("Could not get JSON of AccessToken: %v", errJson)
			RequireAuth(rw, req, la.config, errJson)
			return
		}
		log.Printf("AccessToken: %s", string(jsonAT))

		// start a user session
		// creates a JWT and store it in the cache until it gets deleted by logout of the user or expiration
		// create JWT
		type JWTClaims struct {
			jwtv5.RegisteredClaims
		}
		claims := JWTClaims{
			jwtv5.RegisteredClaims{
				ExpiresAt: jwtv5.NewNumericDate(time.Now().Add(24 * time.Hour)),
				IssuedAt:  jwtv5.NewNumericDate(time.Now()),
				NotBefore: jwtv5.NewNumericDate(time.Now()),
				Issuer:    "",
				Subject:   "",
			},
		}
		// TODO: Add user data like its role to the JWT
		jwt := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims)
		ss, jwtErr := jwt.SignedString([]byte("TODO"))
		if jwtErr != nil {
			log.Printf("Could not create JWT: %v", jwtErr)
			RequireAuth(rw, req, la.config, jwtErr)
			return
		}
		// TODO: check access token is not set yet
		sessionCacheErr := la.cache.Set(&memcache.Item{
			Key:        accessToken.AccessToken,
			Value:      []byte(ss),
			Expiration: int32(time.Now().Unix() + int64(accessToken.ExpiresIn)), // int32 unix time lasts until 2038
		})
		if sessionCacheErr != nil {
			log.Printf("Could not store session in cache: %v", sessionCacheErr)
			RequireAuth(rw, req, la.config, sessionCacheErr)
			return
		}
		ResponseToken(rw, req, la.config, jsonAT)
		return
	}
	// ##############

	session, _ := store.Get(req, la.config.CacheCookieName)
	LoggerDEBUG.Printf("Session details: %v", session)

	username, password, ok := req.BasicAuth()
	username = strings.ToLower(username)

	la.config.Username = username

	if !ok {
		err = errors.New("no valid 'Authorization: Basic xxxx' header found in request")
		RequireAuth(rw, req, la.config, err)
		return
	}

	// #### TODO: PKCE ####
	// code_verifier provided -> opaque token requested
	code_verifier := req.FormValue("code_verifier")
	pkceOK := false
	if code_verifier != "" {
		if code_challenge, ok := session.Values["code_challenge"]; ok {
			h256CodeVerifier := crypto.Hash.New(crypto.SHA256)
			_, err := h256CodeVerifier.Write([]byte(code_verifier))
			if err != nil {
				// TODO: hashing error
			}
			pkceOK = base64.RawURLEncoding.EncodeToString(h256CodeVerifier.Sum(nil)) == code_challenge
		}
	}
	// ###############

	// #### Auth ####
	// auth code requested?
	if oauth2.IsAuthCodeRequest(req) {
		// authcode requested

		authCodeRequest, err := oauth2.AuthCodeFromRequest(req)
		if err != nil {
			// TODO: response with invalid_request
			/*
					the authorization endpoint MUST return the authorization
				error response with the "error" value set to "invalid_request".  The
				"error_description" or the response of "error_uri" SHOULD explain the
				nature of error, e.g., code challenge required.
			*/
			LoggerERROR.Printf("%s", err)
			RequireAuth(rw, req, la.config, err)
			return
		}
		// rfc6749 4.1.1
		// response_type 		- REQUIRED. MUST be "code"
		// client_id 				- REQUIRED. client identifier
		// redirect_uri 		- OPTIONAL.
		// scope 						- OPTIONAL. scope of the access request
		// state 						- RECOMMENDED. opaque value set by client. Needs to be included in redirect of user-agent back to the client.
		// example:
		// GET /authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz
		//     &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb HTTP/1.1
		// Host: server.example.com

		// TODO: check whether the client_id is known and get the registered redirect_uri(s) of this client
		//       if redirect_uris were registered, the set redirect_uri parameter value needs to be one of
		//       the registered redirect_uris
		// if redirect_uri == "" {
		// 	// TODO: take registered redirect_uri
		// 	redirect_uri = "http://localhost/token"
		// }
		//
		// LoggerINFO.Printf("redirect_uri: %s", redirect_uri)
		// LoggerINFO.Printf("scope: %s", scope)
		// LoggerINFO.Printf("state: %s", state)
		// all required parameters valid. Authenticate resource owner.
		conn, err := ldapIdp.Connect(la.config)
		if err != nil {
			LoggerERROR.Printf("%s", err)
			RequireAuth(rw, req, la.config, err)
			return
		}
		defer conn.Close()

		isValidUser, entry, err := ldapIdp.LdapCheckUser(conn, la.config, username, password)

		if !isValidUser {
			defer conn.Close()
			LoggerERROR.Printf("%s", err)
			LoggerERROR.Printf("Authentication failed")
			RequireAuth(rw, req, la.config, err)
			return
		}

		isAuthorized, err := ldapIdp.LdapCheckUserAuthorized(conn, la.config, entry, username)
		if !isAuthorized {
			defer conn.Close()
			LoggerERROR.Printf("%s", err)
			RequireAuth(rw, req, la.config, err)
			return
		}

		LoggerINFO.Printf("Authentication succeeded")

		// rfc6749 4.1.2
		// auth code added as query parameter to the redirection URI using "application/x-www-form-urlencoded" format
		// code - REQUIRED. generated by auth server. MUST expire shortly. Maximum lifetime of 10 minuted RECOMMENDED.
		// 									client MUST NOT use the code more than once. If auth code is used more than once,
		// 									auth server MUST deny the request and SHOULD revoke all tokens previously issued based on
		//  								that auth code. auth code is bound to client_id and redirect_uri.
		// state - REQUIRED. is "state" parameter was present in client auth request. exact value received from client.
		// example:
		// HTTP/1.1 302 Found
		// Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA
		//           &state=xyz
		// store authcodes with expiration timestamp, redirect_uri, scope in a server side cache
		code, err := authCodeRequest.Code() // TODO: generate valid auth code with code_challenge encrypted in it
		// TODO: cache auth code together with client
		// we use memcached as it is easy to use, efficient and has no complex license
		// as we store authcodes and tokens, it would be ok
		// if the client needs to reauthenticate
		// if memcached failed to return the authcode/token due to internal error
		la.gobByteBuf.Reset()
		gobErr := la.gobEncoder.Encode(authCodeRequest)
		if gobErr != nil {
			log.Print(gobErr)
			// TODO: Response error
		}
		errCache := la.cache.Set(&memcache.Item{
			Key:   "code" + code,
			Value: la.gobByteBuf.Bytes(),
		})
		if errCache != nil {
			log.Print(errCache)
			// TODO: Response error
		}
		ResponseAuthCode(rw, req, la.config, code, authCodeRequest.State, authCodeRequest.RedirectURI.String())
		return
	}
	// ##############

	if auth, ok := session.Values["authenticated"].(bool); ok && auth && pkceOK {
		if session.Values["username"] == username {
			LoggerDEBUG.Printf("Session token Valid! Passing request...")
			ServeAuthenicated(la, session, rw, req)
			return
		}
		err = fmt.Errorf("session user: '%s' != Auth user: '%s'. Please, reauthenticate", session.Values["username"], username)
		// Invalidate session.
		session.Values["authenticated"] = false
		session.Values["username"] = username
		session.Options.MaxAge = -1
		session.Save(req, rw)
		RequireAuth(rw, req, la.config, err)
		return
	}

	LoggerDEBUG.Println("No session found! Trying to authenticate in LDAP")

	conn, err := ldapIdp.Connect(la.config)
	if err != nil {
		LoggerERROR.Printf("%s", err)
		RequireAuth(rw, req, la.config, err)
		return
	}

	isValidUser, entry, err := ldapIdp.LdapCheckUser(conn, la.config, username, password)

	if !isValidUser {
		defer conn.Close()
		LoggerERROR.Printf("%s", err)
		LoggerERROR.Printf("Authentication failed")
		RequireAuth(rw, req, la.config, err)
		return
	}

	isAuthorized, err := ldapIdp.LdapCheckUserAuthorized(conn, la.config, entry, username)
	if !isAuthorized {
		defer conn.Close()
		LoggerERROR.Printf("%s", err)
		RequireAuth(rw, req, la.config, err)
		return
	}

	defer conn.Close()

	LoggerINFO.Printf("Authentication succeeded")

	// Set user as authenticated.
	// session.Values["cc"] = code_challenge // must be encrypted
	session.Values["username"] = username
	session.Values["ldap-dn"] = entry.DN
	session.Values["ldap-cn"] = entry.GetAttributeValue("cn")
	session.Values["authenticated"] = true
	session.Save(req, rw)

	ServeAuthenicated(la, session, rw, req)
}

func ServeAuthenicated(la *LdapAuth, session *sessions.Session, rw http.ResponseWriter, req *http.Request) {
	// Sanitize Some Headers Infos.
	if la.config.ForwardUsername {
		username := session.Values["username"].(string)

		req.URL.User = url.User(username)
		req.Header[la.config.ForwardUsernameHeader] = []string{username}

		if la.config.ForwardExtraLdapHeaders && la.config.SearchFilter != "" {
			userDN := session.Values["ldap-dn"].(string)
			userCN := session.Values["ldap-cn"].(string)
			req.Header["Ldap-Extra-Attr-DN"] = []string{userDN}
			req.Header["Ldap-Extra-Attr-CN"] = []string{userCN}
		}
	}

	/*
	 Prevent expose username and password on Header
	 if ForwardAuthorization option is set.
	*/
	if !la.config.ForwardAuthorization {
		req.Header.Del("Authorization")
	}

	la.next.ServeHTTP(rw, req)
}

func ResponseError(w http.ResponseWriter, req *http.Request, redirect_uri string, state string, err error, errDescr string) {
	LoggerDEBUG.Println(err)
	errMsg := strings.Trim(err.Error(), "\x00")
	location, uriErr := url.Parse(redirect_uri)
	// no redirect_uri, response the error without redirect
	if uriErr != nil || location.RawPath == "" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(fmt.Sprintf("%d %s\nError: %s - %s\n", http.StatusBadRequest, http.StatusText(http.StatusBadRequest), errMsg, errDescr)))
		return
	}
	v := url.Values{}
	v.Add("error", errMsg)
	if state != "" {
		v.Add("state", state)
	}
	if errDescr != "" {
		v.Add("error_description", errDescr)
	}
	location.RawQuery = v.Encode()
	w.Header().Add("Location", location.String())
	w.WriteHeader(http.StatusTemporaryRedirect)
}

// ResponseAuthCode responses with an auth code
func ResponseToken(w http.ResponseWriter, req *http.Request, config *ldapIdp.Config, token []byte) error {
	w.Header().Add("Cache-Control", "no-store")
	w.Header().Add("Pragma", "no-cache")
	w.Header().Add("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	w.Write(token)
	return nil
}

// ResponseAuthCode responses with an auth code
func ResponseAuthCode(w http.ResponseWriter, req *http.Request, config *ldapIdp.Config, code string, state string, redirect_uri string) error {
	location, err := url.Parse(redirect_uri)
	LoggerDEBUG.Println("Location: " + location.String())
	if err != nil {
		return err
	}
	v := url.Values{}
	v.Add("code", code)
	if state != "" {
		v.Add("state", state)
	}
	location.RawQuery = v.Encode()
	LoggerDEBUG.Println("location.RawQuery: ", location.RawQuery)
	w.Header().Add("Location", location.String())
	w.WriteHeader(http.StatusTemporaryRedirect)
	return nil
}

// RequireAuth set Auth request.
func RequireAuth(w http.ResponseWriter, req *http.Request, config *ldapIdp.Config, err ...error) {
	LoggerDEBUG.Println(err)
	w.Header().Set("Content-Type", "text/plain")
	if config.WWWAuthenticateHeader {
		wwwHeaderContent := "Basic"
		if config.WWWAuthenticateHeaderRealm != "" {
			wwwHeaderContent = fmt.Sprintf("Basic realm=\"%s\"", config.WWWAuthenticateHeaderRealm)
		}
		w.Header().Set("WWW-Authenticate", wwwHeaderContent)
	}

	w.WriteHeader(http.StatusUnauthorized)

	errMsg := strings.Trim(err[0].Error(), "\x00")
	_, _ = w.Write([]byte(fmt.Sprintf("%d %s\nError: %s\n", http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), errMsg)))
}

// SetLogger define global logger based in logLevel conf.
func SetLogger(level string) {
	switch level {
	case "ERROR":
		LoggerERROR.SetOutput(os.Stderr)
	case "INFO":
		LoggerERROR.SetOutput(os.Stderr)
		LoggerINFO.SetOutput(os.Stdout)
	case "DEBUG":
		LoggerERROR.SetOutput(os.Stderr)
		LoggerINFO.SetOutput(os.Stdout)
		LoggerDEBUG.SetOutput(os.Stdout)
	default:
		LoggerERROR.SetOutput(os.Stderr)
		LoggerINFO.SetOutput(os.Stdout)
	}
}

// LogConfigParams print confs when logLevel is DEBUG.
func LogConfigParams(config *Config) {
	/*
		Make this to prevent error msg
		"Error in Go routine: reflect: call of reflect.Value.NumField on ptr Value"
	*/
	c := *config

	v := reflect.ValueOf(c)
	typeOfS := v.Type()

	for i := 0; i < v.NumField(); i++ {
		LoggerDEBUG.Printf(fmt.Sprint(typeOfS.Field(i).Name, " => '", v.Field(i).Interface(), "'"))
	}
}
