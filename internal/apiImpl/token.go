package archonauth

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/pp23/ldapAuth/internal/ldapIdp"
	"github.com/pp23/ldapAuth/internal/oauth2"
)

// responses with a bearer token
func ResponseToken(w http.ResponseWriter, req *http.Request, config *ldapIdp.Config, token []byte) error {
	w.Header().Add("Cache-Control", "no-store")
	w.Header().Add("Pragma", "no-cache")
	w.Header().Add("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	w.Write(token)
	return nil
}

func (auth *AuthAPI) PostToken(rw http.ResponseWriter, req *http.Request) {
	// #### Token ####
	l := auth.Log
	// opaque token requested?
	if !oauth2.IsOpaqueTokenRequest(req) { // TODO: for better error logging, return missing parameters
		l.ERROR.Printf("Bad Request. No OpaqueTokenRequest: %v", req)
		RequireAuth(rw, req, auth.Auth.config.Ldap, l, fmt.Errorf("Bad Request"))
		return
	}
	// parse the request
	opaqueTokenRequest, err := oauth2.OpaqueTokenFromRequest(req)
	if err != nil {
		l.ERROR.Printf("opaque token error: %v", err)
		RequireAuth(rw, req, auth.Auth.config.Ldap, l, err)
		return
	}
	// get the cached data belonging to the authCode of the request
	item, cacheErr := auth.Cache.Get("code" + opaqueTokenRequest.Code)
	if cacheErr != nil {
		l.ERROR.Printf("opaqueTokenRequest cache error: %v", cacheErr)
		RequireAuth(rw, req, auth.Auth.config.Ldap, l, cacheErr)
		return
	}
	// deserialize the cached data into an oauth2.AuthCode
	_, gobErr := decodeFromBytes[oauth2.AuthCode](item.Value)
	if gobErr != nil {
		l.ERROR.Printf("opaqueTokenRequest decoding error: %v", gobErr)
		RequireAuth(rw, req, auth.Auth.config.Ldap, l, gobErr)
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
		l.ERROR.Printf("opaque token error: %v", err)
		RequireAuth(rw, req, auth.Auth.config.Ldap, l, err)
		return
	}
	jsonAT, errJson := accessToken.Json()
	if errJson != nil {
		l.ERROR.Printf("Could not get JSON of AccessToken: %v", errJson)
		RequireAuth(rw, req, auth.Auth.config.Ldap, l, errJson)
		return
	}
	l.ERROR.Printf("AccessToken: %s", string(jsonAT))

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
		l.ERROR.Printf("Could not create JWT: %v", jwtErr)
		RequireAuth(rw, req, auth.Auth.config.Ldap, l, jwtErr)
		return
	}
	// TODO: check access token is not set yet
	sessionCacheErr := auth.Cache.Set(&memcache.Item{
		Key:        accessToken.AccessToken,
		Value:      []byte(ss),
		Expiration: int32(time.Now().Unix() + int64(accessToken.ExpiresIn)), // int32 unix time lasts until 2038
	})
	if sessionCacheErr != nil {
		l.ERROR.Printf("Could not store session in cache: %v", sessionCacheErr)
		RequireAuth(rw, req, auth.Auth.config.Ldap, l, sessionCacheErr)
		return
	}
	ResponseToken(rw, req, auth.Auth.config.Ldap, jsonAT)
	return
	// ##############
}

// Responses a structured JWT with detailed information. Replaces bearer tokens. Not intended to be used by clientsi directly.
func (auth *AuthAPI) PostJwt(rw http.ResponseWriter, req *http.Request) {
	// #### JWT ####
	l := auth.Log
	// opaque token sent from client, replace it with a JWT
	if authValue, ok := req.Header["Authorization"]; ok {
		if len(strings.Fields(authValue[0])) == 2 && strings.Fields(authValue[0])[0] == "Bearer" {
			opaqueToken := strings.Fields(authValue[0])[1]
			// do we have a session with this opaqueToken?
			item, cacheErr := auth.Cache.Get(opaqueToken)
			if cacheErr != nil {
				l.ERROR.Printf("JWT: opaqueToken \"%s\" not found in cache: %v", opaqueToken, cacheErr)
				RequireAuth(rw, req, auth.Auth.config.Ldap, l, cacheErr)
				return
			}
			// TODO: validate JWT token which were set by us anyway?
			rw.Write(item.Value)
			rw.WriteHeader(http.StatusOK)
		} else {
			l.ERROR.Printf("Bad Request. Authorization header malformed: %v", authValue)
			RequireAuth(rw, req, auth.Auth.config.Ldap, l, fmt.Errorf("Bad Request"))
		}
	} else {
		l.ERROR.Printf("Bad Request. No Authorization header: %v", req.Header)
		RequireAuth(rw, req, auth.Auth.config.Ldap, l, fmt.Errorf("Bad Request"))
	}
	// ########
}
