package archonauth

import (
	"encoding/hex"
	"fmt"
	"log"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/bradfitz/gomemcache/memcache"
	"github.com/go-ldap/ldap/v3"
	"github.com/pp23/ldapAuth/internal/ldapIdp"
	"github.com/pp23/ldapAuth/internal/oauth2"
	"github.com/pp23/ldapAuth/internal/utils"
	"github.com/pp23/ldapAuth/pkg/mapper"
)

// ResponseAuthCode responses with an auth code
func ResponseAuthCode(w http.ResponseWriter, code string, state string, location *url.URL, l *utils.Logger) error {
	l.DEBUG.Println("Location: " + location.String())
	v := url.Values{}
	v.Add("code", code)
	if state != "" {
		v.Add("state", state)
	}
	location.RawQuery = v.Encode()
	l.DEBUG.Println("location.RawQuery: ", location.RawQuery)
	w.Header().Add("Location", location.String())
	w.WriteHeader(http.StatusTemporaryRedirect)
	return nil
}

func (auth *AuthAPI) GetAuth(rw http.ResponseWriter, req *http.Request) {
	l := auth.Log
	username, password, okBasicAuth := req.BasicAuth()
	// auth code requested?
	if okBasicAuth && oauth2.IsAuthCodeRequest(req) {
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
			l.ERROR.Printf("Could not create AuthCode from request: %s", err)
			RequireAuth(rw, req, auth.Auth.config.Ldap, l, err) // TODO: set error object according to rfc
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
			var availableClientIds []string
			for _, c := range auth.Auth.config.OAuth2.Clients {
				availableClientIds = append(availableClientIds, c.ClientId)
			}
			l.ERROR.Printf("ClientId \"%s\" not registered. Available clients: %v", authCodeRequest.ClientId, strings.Join(availableClientIds, ","))
			RequireAuth(rw, req, auth.Auth.config.Ldap, l, fmt.Errorf("Bad Request"))
			return
		}

		if client.RedirectUri != authCodeRequest.RedirectURI.String() {
			l.ERROR.Printf("ClientId \"%s\" has requested redirect uri \"%s\" not registered. Registered redirect uris: %v", client.ClientId, authCodeRequest.RedirectURI.String(), client.RedirectUri)
			RequireAuth(rw, req, auth.Auth.config.Ldap, l, fmt.Errorf("Bad Request"))
			return
		}
		//
		// l.INFO.Printf("redirect_uri: %s", redirect_uri)
		// l.INFO.Printf("scope: %s", scope)
		// l.INFO.Printf("state: %s", state)
		// all required parameters valid. Authenticate resource owner.
		var conn *ldap.Conn
		var ldapConnErr error
		// TODO: make retries configurable
		for i := 0; i < 10; i += 1 {
			conn, ldapConnErr = ldapIdp.Connect(auth.Auth.config.Ldap)
			if ldapConnErr != nil {
				l.DEBUG.Printf("LDAP-Connect-Retry [%d/10]: %v", i, ldapConnErr)
				continue
			} else {
				break
			}
		}
		if ldapConnErr != nil {
			l.ERROR.Printf("LDAP-Connect: %s", ldapConnErr)
			RequireAuth(rw, req, auth.Auth.config.Ldap, l, ldapConnErr)
			return
		}
		defer conn.Close()

		// entry is the LDAP user entry
		auth.Auth.config.Ldap.SearchFilter = "(&(cn=" + username + ")(objectClass=*))" // search for the user and all its attributes
		isValidUser, entry, err := ldapIdp.LdapCheckUser(conn, auth.Auth.config.Ldap, username, password)

		if !isValidUser {
			defer conn.Close()
			l.ERROR.Printf("%s", err)
			l.ERROR.Printf("Authentication failed")
			RequireAuth(rw, req, auth.Auth.config.Ldap, l, err)
			return
		}

		// since we have the user entry already, let's map the keys to claims
		l.INFO.Printf("LDAP-Entry: %v", entry.Attributes)
		l.INFO.Printf("LDAP-Entry: DN: %s", entry.DN)
		l.INFO.Printf("LDAP-Entry cn: %s", entry.GetAttributeValue("cn"))
		entry.Print()
		for _, attribute := range entry.Attributes {
			l.INFO.Printf("LDAP attribute: %s = %v", attribute.Name, attribute.Values)
		}
		// Load the mappers from the clients config
		keyClaimMapping := LdapClaimMapperFromConfig(client.IdpClaimMappers)
		// initialize the claimMapper with the Key/Values from the IdP
		claimMapper := &mapper.SequentialMapper[string, any]{
			// iterator over key-values of LDAP entry
			KVIter: LdapAttributesToMap(slices.Values(entry.Attributes)),
			ErrorFn: func(err error, key string, value any) bool {
				// true: ignore error
				return true
			},
		}
		// do the mapping
		jwtClaims := oauth2.JWTPrivateClaims(maps.Collect(claimMapper.Map(keyClaimMapping.LdapKeyJWTClaimMapFn)))
		plainJwtClaims, jwtClaimsEncErr := encodeToBytes(jwtClaims)
		if jwtClaimsEncErr != nil {
			l.ERROR.Printf("Could not gob-encode JWT Private Claims: %v", jwtClaimsEncErr)
			// TODO: Respond error
			return
		}
		if auth.Auth.config.Cache.Encryption != nil {
			authCodeRequest.JWTClaims, jwtClaimsEncErr = auth.Auth.config.Cache.Encryption.Encrypt(plainJwtClaims)
			if jwtClaimsEncErr != nil {
				l.ERROR.Printf("Could not encrypt gob-encoded JWT Private Claims: %v", jwtClaimsEncErr)
				// TODO: Respond error
				return
			}
		} else {
			// no cache encryption configured, continue with plain JWT claims
			authCodeRequest.JWTClaims = plainJwtClaims
		}

		l.INFO.Printf("Authentication succeeded: %s", strings.Join(slices.Collect(maps.Keys(jwtClaims)), ","))

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
		// it would be ok if the client needs to reauthenticate in case memcached failed to return the authcode/token
		data, gobErr := encodeToBytes(authCodeRequest)
		if gobErr != nil {
			log.Print(gobErr)
			// TODO: Response error
		}
		l.DEBUG.Printf("AuthCode Cache data: %s", hex.Dump(data))
		errCache := auth.Cache.Set(&memcache.Item{
			Key:   "code" + code,
			Value: data,
		})
		if errCache != nil {
			l.ERROR.Printf("cache: Could not set cache entry: %v", errCache)
			// TODO: Response error
		}
		ResponseAuthCode(rw, code, authCodeRequest.State, authCodeRequest.RedirectURI, l)
		return
	}

	if !okBasicAuth {
		l.ERROR.Print("Credentials missing: BasicAuth required to get auth code")
		RequireAuth(rw, req, auth.Auth.config.Ldap, l, fmt.Errorf("Bad Request."))
	}
	if !oauth2.IsAuthCodeRequest(req) {
		l.ERROR.Print("AuthCode request missing: ?response_type=code")
		RequireAuth(rw, req, auth.Auth.config.Ldap, l, fmt.Errorf("Bad Request."))
	}
}
