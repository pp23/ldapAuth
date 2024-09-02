package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/pp23/ldapAuth/cmd/archonauth/test"
)

// global cache
var mockMemcache test.MockMemCache = test.NewMockMemCache()

func TestAuthCodeResponseSuccess(t *testing.T) {
	ctx := context.Background()
	cfg := CreateConfig()
	// next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	cfg.Ldap.LogLevel = "DEBUG"
	cfg.Ldap.URL = "ldap://localhost"
	ldapAuth, err := New(ctx, cfg)
	if err != nil {
		LoggerERROR.Printf("%v", err)
		os.Exit(1)
	}
	authApi := AuthAPI{
		Auth: ldapAuth,
	}
	handler := NewChiRouter(&authApi)

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
