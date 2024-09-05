package main

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/pp23/ldapAuth/cmd/archonauth/test"
)

// global cache
var mockMemcache test.MockMemCache = test.NewMockMemCache()

func TestAuthCodeResponseSuccess(t *testing.T) {
	cfg := test.CreateConfig()
	authApi := test.NewAuthApi(cfg, t)
	handler := NewChiRouter(authApi)

	excpectedRedirectURI := "https://localhost:1234/token"
	expectedCodeChallenge := "challenge123"
	expectedState := "123"
	req := httptest.NewRequest(
		"POST",
		"http://localhost/auth?state="+expectedState+"&redirect_uri="+excpectedRedirectURI+"&client_id=abc&response_type=code&code_challenge="+expectedCodeChallenge,
		nil,
	)
	w := httptest.NewRecorder()
	t.Log("MockLdapServer URL: " + cfg.Ldap.URL)
	mockLdapServer := test.MockTCPServer{}
	mockMemcachedServer := test.MockTCPServer{}
	wg := sync.WaitGroup{}
	wg.Add(2)
	// memcachedServer
	t.Log("Start MockMemcachedServer")
	go func() {
		defer wg.Done()
		mockMemcachedServer.Run(
			11211,
			mockMemcache.MockMemCachedMsgHandler,
			func(err error) { t.Error("Error: ", err) },
		)
	}()
	// LDAPServer
	go func() {
		defer wg.Done()
		mockLdapServer.Run(
			1389,
			test.MockBindResponse,
			func(err error) { t.Error("Error: ", err) /* t.Error() causes the test to fail */ },
		)
	}()
	cfg.Ldap.Port = 1389
	req.SetBasicAuth("user02", "secret") // password gets not checked as we mock the ldap server which accepts every user
	handler.ServeHTTP(w, req)            // request an auth code. The user auth is done against the mocked ldap server
	resp := w.Result()
	t.Log(resp.StatusCode)
	// auth code reponse should redirect to provided redirect_uri
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("Expected status code %v, got %v", http.StatusTemporaryRedirect, resp.StatusCode)
	}
	locationURL, err := resp.Location()
	if err != nil {
		t.Fatal("No location redirect: ", err)
	}
	if excpectedRedirectURI != locationURL.Scheme+"://"+locationURL.Host+locationURL.EscapedPath() {
		t.Fatalf("Redirect URI not matching. Expected %s, got %s", excpectedRedirectURI, locationURL.Scheme+"://"+locationURL.Host+locationURL.EscapedPath())
	}
	queryValues := locationURL.Query()
	// the new location uri must include a code and state parameter
	mandatoryParameters := []string{"code", "state"}
	for _, mandatoryParameter := range mandatoryParameters {
		if p, ok := queryValues[mandatoryParameter]; ok {
			if len(p) != 1 {
				t.Fatalf("More than one \"%s\" parameter set", mandatoryParameter)
			}
			if p[0] == "" {
				t.Fatalf("\"%s\" parameter not set in response", mandatoryParameter)
			}
		}
	}
	if len(queryValues) != 2 {
		t.Fatalf("Not exact 2 query parameters given. Expected %v, got %v", mandatoryParameters, queryValues)
	}
	// body must be empty as the new redirect location contains all needed parameters
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal("Error while reading body: ", err)
	}
	if len(respBody) != 0 {
		t.Fatalf("Expected no body, got %s [%v]", string(respBody), len(respBody))
	}
	mockMemcachedServer.Close()
	mockLdapServer.Close()
	wg.Wait()
}

// exchange an auth code with an access token
// as we want to use the phantom token approach, the access token must not include structured data
// see also https://curity.io/resources/learn/phantom-token-pattern/
func TestOpaqueTokenResponseSuccess(t *testing.T) {
	cfg := test.CreateConfig()
	authApi := test.NewAuthApi(cfg, t)
	handler := NewChiRouter(authApi)

	expectedHeaders := map[string]string{
		"Content-Type": "application/json;charset=UTF-8",
		// authorization server MUST include the HTTP "Cache-Control"
		// response header field [RFC2616] with a value of "no-store" in any
		// response containing tokens, credentials, or other sensitive
		// information
		"Cache-Control": "no-store",
		// as well as the "Pragma" response header field [RFC2616]
		// with a value of "no-cache"
		"Pragma": "no-cache",
	}
	excpectedRedirectURI := "https://localhost:1234/token"
	expectedCodeChallenge := "challenge123"
	expectedState := "123"
	req := httptest.NewRequest(
		"POST",
		"http://localhost/auth?state="+expectedState+"&redirect_uri="+excpectedRedirectURI+"&client_id=abc&response_type=code&code_challenge="+expectedCodeChallenge,
		nil,
	)
	w := httptest.NewRecorder()
	cfg.Ldap.LogLevel = "DEBUG"
	cfg.Ldap.URL = "ldap://localhost"
	t.Log("MockLdapServer URL: " + cfg.Ldap.URL)
	mockLdapServer := test.MockTCPServer{}
	mockMemcachedServer := test.MockTCPServer{}
	wg := sync.WaitGroup{}
	wg.Add(2)
	// memcachedServer
	go func() {
		defer wg.Done()
		mockMemcachedServer.Run(
			11211,
			mockMemcache.MockMemCachedMsgHandler,
			func(err error) { t.Error("Error: ", err) },
		)
	}()
	go func() {
		defer wg.Done()
		mockLdapServer.Run(
			1389,
			test.MockBindResponse,
			func(err error) { t.Error("Error: ", err) /* t.Error() causes the test to fail */ },
		)
	}()
	cfg.Ldap.Port = 1389
	req.SetBasicAuth("user02", "secret")
	handler.ServeHTTP(w, req)
	resp := w.Result()
	locationURL, err := resp.Location()
	if err != nil {
		t.Fatal(err)
	}
	authCode := locationURL.Query().Get("code")
	t.Logf("AuthCode: %s", authCode)
	locationURL.RawFragment = ""
	locationURL.RawQuery = "" // no query in token request url, but in the body
	reqBodyValues := url.Values{}
	reqBodyValues.Add("grant_type", "authorization_code")
	reqBodyValues.Add("code", authCode)
	reqBodyValues.Add("redirect_uri", excpectedRedirectURI)
	reqBodyValues.Add("client_id", "abc") // required, if the client is not authenticating with the authorization server
	reqRedirect := httptest.NewRequest(
		"GET", // TODO: POST? What does the RFC tell here?
		locationURL.String(),
		nil,
	)
	reqRedirect.PostForm = reqBodyValues // sets the content-type correct
	b, _ := io.ReadAll(reqRedirect.Body)
	t.Logf("Opaque token request body: %s", string(b))
	w = httptest.NewRecorder() // new recorder required to prevent checking previous results
	handler.ServeHTTP(w, reqRedirect)
	respToken := w.Result()
	if respToken.Status != "200 OK" {
		t.Fatalf("Expected token response status \"200 OK\", got \"%s\"", respToken.Status)
	}
	for expectedHeaderKey, expectedHeaderValue := range expectedHeaders {
		if headerValue, ok := respToken.Header[expectedHeaderKey]; !ok {
			t.Fatalf("%s header not found in token response", expectedHeaderKey)
		} else {
			if headerValue[0] != expectedHeaderValue {
				t.Fatalf("Expected value \"%s\" for header \"%s\", got \"%s\"", expectedHeaderValue, expectedHeaderKey, headerValue[0])
			}
		}
	}
	resObj := make(map[string]interface{})
	body, err := io.ReadAll(respToken.Body)
	if err != nil {
		t.Error(err)
	}
	errJson := json.Unmarshal(body, &resObj)
	if errJson != nil {
		t.Error(errJson)
	}
	t.Log(resObj)
	for _, k := range []string{"access_token", "token_type", "expires_in", "refresh_token", "scope"} {
		if _, ok := resObj[k]; !ok {
			t.Errorf("Missing key in response access token json object: %s, got response %v", k, resObj)
		}
	}
	// check for not long enough access tokens, UUIDs have 32 characters + 4 dashes
	if len(resObj["access_token"].(string)) < 36 {
		t.Errorf("Access token should have sufficient lenght of at least an UUID. Expected 36 characters, got %v (%s)", len(resObj["access_token"].(string)), resObj["access_token"].(string))
	}
	if resObj["token_type"].(string) != "bearer" {
		t.Errorf("Expected token_type bearer, got %s", resObj["token_type"].(string))
	}
	if resObj["expires_in"].(float64) < 600 {
		t.Errorf("Expected expiration of at least 600s, got %v", resObj["expires_in"].(float64))
	}
	// TODO: test whether the token is not a JWT as we expect only an opaque token
	mockMemcachedServer.Close()
	mockLdapServer.Close()
	wg.Wait()
}

func TestJWTTokenSuccess(t *testing.T) {
	cfg := test.CreateConfig()
	authApi := test.NewAuthApi(cfg, t)
	handler := NewChiRouter(authApi)

	excpectedRedirectURI := "https://localhost:1234/token"
	expectedCodeChallenge := "challenge123"
	expectedState := "123"
	req := httptest.NewRequest(
		"POST",
		"http://localhost/auth?state="+expectedState+"&redirect_uri="+excpectedRedirectURI+"&client_id=abc&response_type=code&code_challenge="+expectedCodeChallenge,
		nil,
	)
	w := httptest.NewRecorder()
	cfg.Ldap.LogLevel = "DEBUG"
	cfg.Ldap.URL = "ldap://localhost"
	t.Log("MockLdapServer URL: " + cfg.Ldap.URL)
	mockLdapServer := test.MockTCPServer{}
	mockMemcachedServer := test.MockTCPServer{}
	wg := sync.WaitGroup{}
	wg.Add(2)
	// memcachedServer
	go func() {
		defer wg.Done()
		mockMemcachedServer.Run(
			11211,
			mockMemcache.MockMemCachedMsgHandler,
			func(err error) { t.Error("Error: ", err) },
		)
	}()
	go func() {
		defer wg.Done()
		mockLdapServer.Run(
			1389,
			test.MockBindResponse,
			func(err error) { t.Error("Error: ", err) /* t.Error() causes the test to fail */ },
		)
	}()
	cfg.Ldap.Port = 1389
	req.SetBasicAuth("user02", "secret")
	handler.ServeHTTP(w, req)
	resp := w.Result()
	locationURL, err := resp.Location()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Location-URL: %s", locationURL)
	authCode := locationURL.Query().Get("code")
	t.Logf("AuthCode: %s", authCode)
	locationURL.RawFragment = ""
	locationURL.RawQuery = "" // no query in token request url, but in the body
	reqBodyValues := url.Values{}
	reqBodyValues.Add("grant_type", "authorization_code")
	reqBodyValues.Add("code", authCode)
	reqBodyValues.Add("redirect_uri", excpectedRedirectURI)
	reqBodyValues.Add("client_id", "abc") // required, if the client is not authenticating with the authorization server
	reqRedirect := httptest.NewRequest(
		"GET",
		locationURL.String(),
		nil,
	)
	reqRedirect.PostForm = reqBodyValues // sets the content-type correct
	b, _ := io.ReadAll(reqRedirect.Body)
	t.Logf("Opaque token request body: %s", string(b))
	w = httptest.NewRecorder() // new recorder required to prevent checking previous results
	handler.ServeHTTP(w, reqRedirect)
	respToken := w.Result()
	resObj := make(map[string]interface{})
	body, err := io.ReadAll(respToken.Body)
	if err != nil {
		t.Error(err)
	}
	errJson := json.Unmarshal(body, &resObj)
	if errJson != nil {
		t.Error(errJson)
	}
	if at, ok := resObj["access_token"]; ok {
		getReq := httptest.NewRequest(
			"GET",
			"http://localhost/jwt",
			nil,
		)
		getReq.Header["Authorization"] = []string{"Bearer " + at.(string)}
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, getReq)
		resp := w.Result()
		if resp.StatusCode != 200 {
			t.Errorf("Expected status code 200 from GET request, got %v", resp.Status)
		}
		jwtBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Errorf("Could not read JWT response body: %v", err)
		}
		jwtString := string(jwtBytes)
		t.Logf("Got JWT: %s", jwtString)
		jwtParser := jwtv5.NewParser()
		jwt, jwtErr := jwtParser.Parse(jwtString, func(token *jwtv5.Token) (interface{}, error) {
			return []byte("TODO"), nil
		})
		if jwtErr != nil {
			t.Errorf("Could not parse JWT string: %v", jwtErr)
		}
		t.Logf("JWT: %v", jwt)
	}
	mockMemcachedServer.Close()
	mockLdapServer.Close()
	wg.Wait()
}
