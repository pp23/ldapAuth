package archonauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/gob"
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
	"github.com/go-ldap/ldap/v3"
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/sessions"

	"github.com/pp23/ldapAuth/cmd/archonauth/config"
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
	config     *config.Config
	cache      *memcache.Client
	gobEncoder *gob.Encoder
	gobDecoder *gob.Decoder
	gobByteBuf *bytes.Buffer
}

// New created a new LdapAuth plugin.
func New(ctx context.Context, config *config.Config) (*LdapAuth, error) {
	SetLogger(config.Ldap.LogLevel)
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
		config:     config,
		cache:      memcache.New(config.Cache.Host),
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

func ServeAuthenicated(la *LdapAuth, session *sessions.Session, rw http.ResponseWriter, req *http.Request) {
	// Sanitize Some Headers Infos.
	if la.config.Ldap.ForwardUsername {
		username := session.Values["username"].(string)

		req.URL.User = url.User(username)
		req.Header[la.config.Ldap.ForwardUsernameHeader] = []string{username}

		if la.config.Ldap.ForwardExtraLdapHeaders && la.config.Ldap.SearchFilter != "" {
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
	if !la.config.Ldap.ForwardAuthorization {
		req.Header.Del("Authorization")
	}

	// TODO: response instead of using next handler, la.next.ServeHTTP(rw, req)
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
func LogConfigParams(config *config.Config) {
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

type AuthAPI struct {
	Auth *LdapAuth
}

func (auth *AuthAPI) GetAuth(rw http.ResponseWriter, req *http.Request) {
	// #### Auth ####

	// auth code requested?
	if username, password, ok := req.BasicAuth(); ok && oauth2.IsAuthCodeRequest(req) {
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
			RequireAuth(rw, req, auth.Auth.config.Ldap, err)
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

		// check whether the client_id is known and get the registered redirect_uri(s) of this client
		// if redirect_uris were registered, the set redirect_uri parameter value needs to be one of
		// the registered redirect_uris
		// the client does not need to authenticate here. Client authentication happens when the client requests a token. (see rfc6749, 4.1 (D))
		client := func() *oauth2.OAuth2Client {
			if auth.Auth.config.OAuth2 == nil {
				return nil
			}
			for _, c := range auth.Auth.config.OAuth2.Clients {
				if c.ClientId == authCodeRequest.ClientId {
					return c
				}
			}
			return nil
		}()
		if client == nil {
			LoggerERROR.Printf("ClientId \"%s\" not registered. Available clients: %v", authCodeRequest.ClientId, auth.Auth.config.OAuth2.Clients)
			RequireAuth(rw, req, auth.Auth.config.Ldap, fmt.Errorf("Bad Request"))
			return
		}

		if client.RedirectUri != authCodeRequest.RedirectURI.RequestURI() {
			LoggerERROR.Printf("ClientId \"%s\" has requested redirect uri \"%s\" not registered. Registered redirect uris: %v", client.ClientId, authCodeRequest.RedirectURI.RequestURI(), client.RedirectUri)
			RequireAuth(rw, req, auth.Auth.config.Ldap, fmt.Errorf("Bad Request"))
			return
		}
		//
		// LoggerINFO.Printf("redirect_uri: %s", redirect_uri)
		// LoggerINFO.Printf("scope: %s", scope)
		// LoggerINFO.Printf("state: %s", state)
		// all required parameters valid. Authenticate resource owner.
		var conn *ldap.Conn
		var ldapConnErr error
		// TODO: make retries configurable
		for i := 0; i < 10; i += 1 {
			conn, ldapConnErr = ldapIdp.Connect(auth.Auth.config.Ldap)
			if ldapConnErr != nil {
				LoggerDEBUG.Printf("LDAP-Connect-Retry [%d/10]: %v", i, ldapConnErr)
				continue
			} else {
				break
			}
		}
		if ldapConnErr != nil {
			LoggerERROR.Printf("LDAP-Connect: %s", ldapConnErr)
			RequireAuth(rw, req, auth.Auth.config.Ldap, ldapConnErr)
			return
		}
		defer conn.Close()

		isValidUser, entry, err := ldapIdp.LdapCheckUser(conn, auth.Auth.config.Ldap, username, password)

		if !isValidUser {
			defer conn.Close()
			LoggerERROR.Printf("%s", err)
			LoggerERROR.Printf("Authentication failed")
			RequireAuth(rw, req, auth.Auth.config.Ldap, err)
			return
		}

		isAuthorized, err := ldapIdp.LdapCheckUserAuthorized(conn, auth.Auth.config.Ldap, entry, username)
		if !isAuthorized {
			defer conn.Close()
			LoggerERROR.Printf("%s", err)
			RequireAuth(rw, req, auth.Auth.config.Ldap, err)
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
		auth.Auth.gobByteBuf.Reset()
		gobErr := auth.Auth.gobEncoder.Encode(authCodeRequest)
		if gobErr != nil {
			log.Print(gobErr)
			// TODO: Response error
		}
		errCache := auth.Auth.cache.Set(&memcache.Item{
			Key:   "code" + code,
			Value: auth.Auth.gobByteBuf.Bytes(),
		})
		if errCache != nil {
			LoggerERROR.Printf("cache: Could not set cache entry: %v", errCache)
			// TODO: Response error
		}
		ResponseAuthCode(rw, req, auth.Auth.config.Ldap, code, authCodeRequest.State, authCodeRequest.RedirectURI.String())
		return
	}
	RequireAuth(rw, req, auth.Auth.config.Ldap, fmt.Errorf("Bad Request"))
	// ##############
}

func (auth *AuthAPI) PostToken(rw http.ResponseWriter, req *http.Request) {
	// #### Token ####
	// opaque token requested?
	if !oauth2.IsOpaqueTokenRequest(req) {
		LoggerERROR.Printf("Bad Request. No OpaqueTokenRequest: %v", req)
		RequireAuth(rw, req, auth.Auth.config.Ldap, fmt.Errorf("Bad Request"))
		return
	}
	// parse the request
	opaqueTokenRequest, err := oauth2.OpaqueTokenFromRequest(req)
	if err != nil {
		LoggerERROR.Printf("opaque token error: %v", err)
		RequireAuth(rw, req, auth.Auth.config.Ldap, err)
		return
	}
	// get the cached data belonging to the authCode of the request
	item, cacheErr := auth.Auth.cache.Get("code" + opaqueTokenRequest.Code)
	if cacheErr != nil {
		LoggerERROR.Printf("opaqueTokenRequest cache error: %v", cacheErr)
		RequireAuth(rw, req, auth.Auth.config.Ldap, cacheErr)
		return
	}
	// deserialize the cached data into an oauth2.AuthCode
	auth.Auth.gobByteBuf.Reset()
	_, bufErr := auth.Auth.gobByteBuf.Write(item.Value)
	if bufErr != nil {
		LoggerERROR.Printf("opaqueTokenRequest decoding buffer error: %v", bufErr)
		RequireAuth(rw, req, auth.Auth.config.Ldap, bufErr)
		return
	}
	var authCodeRequest oauth2.AuthCode
	gobErr := auth.Auth.gobDecoder.Decode(&authCodeRequest)
	if gobErr != nil {
		LoggerERROR.Printf("opaqueTokenRequest decoding error: %v", gobErr)
		RequireAuth(rw, req, auth.Auth.config.Ldap, gobErr)
		return
	}
	// TODO: Check PKCE encoded in the authCode with that from the request
	// TODO: Check client credentials and authenticate the client

	// see rfc6749 4.1.3
	// TODO: require client auth for confidential clients or for any client that was issued client credentials
	// TODO: authenticate the client
	// TODO: ensure authCode was issued to the client
	// TODO: ensure redirect_uri is present if it was included in the initial auth request. Values need to be identical.

	// authCode found in cache and is therefore valid. Generate an access token.
	accessToken, err := opaqueTokenRequest.GenerateAccessToken(600)
	if err != nil {
		LoggerERROR.Printf("opaque token error: %v", err)
		RequireAuth(rw, req, auth.Auth.config.Ldap, err)
		return
	}
	jsonAT, errJson := accessToken.Json()
	if errJson != nil {
		LoggerERROR.Printf("Could not get JSON of AccessToken: %v", errJson)
		RequireAuth(rw, req, auth.Auth.config.Ldap, errJson)
		return
	}
	LoggerERROR.Printf("AccessToken: %s", string(jsonAT))

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
		LoggerERROR.Printf("Could not create JWT: %v", jwtErr)
		RequireAuth(rw, req, auth.Auth.config.Ldap, jwtErr)
		return
	}
	// TODO: check access token is not set yet
	sessionCacheErr := auth.Auth.cache.Set(&memcache.Item{
		Key:        accessToken.AccessToken,
		Value:      []byte(ss),
		Expiration: int32(time.Now().Unix() + int64(accessToken.ExpiresIn)), // int32 unix time lasts until 2038
	})
	if sessionCacheErr != nil {
		LoggerERROR.Printf("Could not store session in cache: %v", sessionCacheErr)
		RequireAuth(rw, req, auth.Auth.config.Ldap, sessionCacheErr)
		return
	}
	ResponseToken(rw, req, auth.Auth.config.Ldap, jsonAT)
	return
	// ##############
}

func (auth *AuthAPI) PostJwt(rw http.ResponseWriter, req *http.Request) {
	// #### JWT ####
	// opaque token sent from client, replace it with a JWT
	if authValue, ok := req.Header["Authorization"]; ok {
		if len(strings.Fields(authValue[0])) == 2 && strings.Fields(authValue[0])[0] == "Bearer" {
			opaqueToken := strings.Fields(authValue[0])[1]
			// do we have a session with this opaqueToken?
			item, cacheErr := auth.Auth.cache.Get(opaqueToken)
			if cacheErr != nil {
				log.Printf("JWT: opaqueToken \"%s\" not found in cache: %v", opaqueToken, cacheErr)
				RequireAuth(rw, req, auth.Auth.config.Ldap, cacheErr)
				return
			}
			// TODO: validate JWT token which were set by us anyway?
			rw.Write(item.Value)
			rw.WriteHeader(http.StatusOK)
		} else {
			LoggerERROR.Printf("Bad Request. Authorization header malformed: %v", authValue)
			RequireAuth(rw, req, auth.Auth.config.Ldap, fmt.Errorf("Bad Request"))
		}
	} else {
		LoggerERROR.Printf("Bad Request. No Authorization header: %v", req.Header)
		RequireAuth(rw, req, auth.Auth.config.Ldap, fmt.Errorf("Bad Request"))
	}
	// ########
}
