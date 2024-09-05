// Package ldapAuth a ldap authentication plugin.
// nolint
package ldapAuth

import (
	"context"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"

	"github.com/gorilla/sessions"
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
	next         http.Handler
	name         string
	config       *Config
	sessionStore *sessions.CookieStore
	client       *http.Client
}

// Config the plugin configuration.
type Config struct {
	Enabled           bool   `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	AuthUri           string `json:"auth_uri" yaml:"auth_uri"`
	OpaqueTokenUri    string `json:"opaque_token_uri" yaml:"opaque_token_uri"`
	JwtTokenUri       string `json:"jwt_token_uri" yaml:"jwt_token_uri"`
	LogLevel          string `json:"log_level,omitempty" yaml:"log_level,omitempty"`
	CacheTimeout      uint32 `json:"cacheTimeout,omitempty" yaml:"cacheTimeout,omitempty"`
	CacheCookieName   string `json:"cacheCookieName,omitempty" yaml:"cacheCookieName,omitempty"`
	CacheCookiePath   string `json:"cacheCookiePath,omitempty" yaml:"cacheCookiePath,omitempty"`
	CacheCookieSecure bool   `json:"cacheCookieSecure,omitempty" yaml:"cacheCookieSecure,omitempty"`
	CacheKey          string `json:"cacheKey,omitempty" yaml:"cacheKey,omitempty"`
}

func CreateConfig() *Config {
	return &Config{}
}

// New created a new LdapAuth plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	SetLogger(config.LogLevel)

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
	store = sessions.NewCookieStore([]byte(config.CacheKey), encKey)
	store.Options = &sessions.Options{
		HttpOnly: true,
		MaxAge:   int(config.CacheTimeout),
		Path:     config.CacheCookiePath,
		Secure:   config.CacheCookieSecure,
	}

	return &LdapAuth{
		name:         name,
		next:         next,
		config:       config,
		sessionStore: store,
		client: &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (la *LdapAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if !la.config.Enabled {
		LoggerINFO.Printf("%s Disabled! Passing request...", la.name)
		la.next.ServeHTTP(rw, req)
		return
	}

	session, err := la.sessionStore.New(req, "session")
	if err != nil {
		LoggerERROR.Printf("Could not create new cookie session: %v", err)
		RequireAuth(rw, req, la.config, err)
	}
	// Set user as authenticated.
	// session.Values["cc"] = code_challenge // must be encrypted
	session.Values["authenticated"] = true
	session.Save(req, rw)

	// #### exchange opaque token with JWT ####
	if len(req.Header["Authorization"]) != 1 {
		LoggerERROR.Printf("Request does not contain exactly one \"Authorization\" header. Headers: %v", req.Header)
		RequireAuth(rw, req, la.config, fmt.Errorf("Bad Request"))
		return
	}
	authHeader := req.Header["Authorization"][0]
	if len(strings.Fields(authHeader)) != 2 {
		LoggerERROR.Printf("Requests Authorization header has not 2 string fields, namely \"Bearer\" and the opaque token. Authorization header: %v", authHeader)
		RequireAuth(rw, req, la.config, fmt.Errorf("Bad Request"))
		return
	}
	if strings.Fields(authHeader)[0] != "Bearer" {
		LoggerERROR.Printf("No bearer token. Authorization header: %v", authHeader)
		RequireAuth(rw, req, la.config, fmt.Errorf("Bad Request"))
		return
	}
	opaqueToken := strings.Fields(authHeader)[1]
	// request the JWT with the opaqueToken
	jwtReq, reqErr := http.NewRequest("GET", la.config.JwtTokenUri, nil)
	if reqErr != nil {
		LoggerERROR.Printf("Could not create request to JWT URI: %v", reqErr)
		RequireAuth(rw, req, la.config, fmt.Errorf("Bad Request"))
		return
	}
	jwtReq.Header["Authorization"] = []string{
		"bearer " + opaqueToken,
	}
	resp, respErr := la.client.Do(jwtReq)
	if respErr != nil {
		LoggerERROR.Printf("Could not request JWT: %v", respErr)
		RequireAuth(rw, req, la.config, fmt.Errorf("Bad Request"))
		return
	}
	jwtBytes, jwtErr := ioutil.ReadAll(resp.Body)
	if jwtErr != nil {
		LoggerERROR.Printf("Could not read JWT from response body: %v", respErr)
		RequireAuth(rw, req, la.config, fmt.Errorf("Bad Request"))
		return
	}
	// replace Authorization header in the original request with the JWT
	req.Header["Authorization"] = []string{
		"bearer " + string(jwtBytes),
	}
	// ########

	ServeAuthenicated(la, session, rw, req)
}

func ServeAuthenicated(la *LdapAuth, session *sessions.Session, rw http.ResponseWriter, req *http.Request) {
	// Sanitize Some Headers Infos.
	// if la.config.ForwardUsername {
	// 	username := session.Values["username"].(string)
	//
	// 	req.URL.User = url.User(username)
	// 	req.Header[la.config.ForwardUsernameHeader] = []string{username}
	//
	// 	if la.config.ForwardExtraLdapHeaders && la.config.SearchFilter != "" {
	// 		userDN := session.Values["ldap-dn"].(string)
	// 		userCN := session.Values["ldap-cn"].(string)
	// 		req.Header["Ldap-Extra-Attr-DN"] = []string{userDN}
	// 		req.Header["Ldap-Extra-Attr-CN"] = []string{userCN}
	// 	}
	// }
	//
	// /*
	//  Prevent expose username and password on Header
	//  if ForwardAuthorization option is set.
	// */
	// if !la.config.ForwardAuthorization {
	// 	req.Header.Del("Authorization")
	// }

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

// RequireAuth set Auth request.
func RequireAuth(w http.ResponseWriter, req *http.Request, config *Config, err ...error) {
	LoggerDEBUG.Println(err)
	// w.Header().Set("Content-Type", "text/plain")
	// if config.WWWAuthenticateHeader {
	// 	wwwHeaderContent := "Basic"
	// 	if config.WWWAuthenticateHeaderRealm != "" {
	// 		wwwHeaderContent = fmt.Sprintf("Basic realm=\"%s\"", config.WWWAuthenticateHeaderRealm)
	// 	}
	// 	w.Header().Set("WWW-Authenticate", wwwHeaderContent)
	// }

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
