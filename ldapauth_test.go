// Package ldapAuth_test a test suit for ldap authentication plugin.
// nolint
package ldapAuth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/pp23/ldapAuth"
	config "github.com/pp23/ldapAuth/cmd/archonauth/config"
	"github.com/pp23/ldapAuth/cmd/archonauth/test"
)

func TestDemo(t *testing.T) {
	cfg := ldapAuth.CreateConfig()
	cfg.JwtTokenUri = "http://localhost:8080/jwt"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := ldapAuth.New(ctx, next, cfg, "ldapAuth")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)
}

func assertHeader(t *testing.T, req *http.Request, key, expected string) {
	t.Helper()

	if req.Header.Get(key) != expected {
		t.Errorf("invalid header value: %s", req.Header.Get(key))
	}
}

func getAuthApiHandler(cfg *config.Config, t *testing.T) http.Handler {
	api := test.NewAuthApi(cfg, t)
	return test.NewAuthApiHandler(api)
}

func getAccessToken(cfg *config.Config, handler http.Handler, testConfig test.TestConfig, t *testing.T) string {
	return test.GetOpaqueToken(handler, cfg, testConfig, t)
}

func TestJWTTokenSuccess(t *testing.T) {
	testCfg, testCfgErr := test.TestConfigFromEnv()
	if testCfgErr != nil {
		t.Fatal(testCfgErr)
	}
	wg := sync.WaitGroup{}
	mockMemcache := test.NewMockMemCache()
	mockMemcachedServer := test.RunMockMemCacheServer(&wg, &mockMemcache, t)
	mockLdapServer := test.RunMockLdapServer(&wg, t)
	cfg := test.CreateConfig()
	handler := getAuthApiHandler(cfg, t)
	at := getAccessToken(cfg, handler, testCfg, t)
	getReq := httptest.NewRequest(
		"GET",
		"http://localhost/data",
		nil,
	)
	t.Logf("Current Cache: %v", mockMemcache)
	getReq.Header["Authorization"] = []string{"Bearer " + at}
	w := httptest.NewRecorder()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		t.Logf("Next: %v", req.Header)
		auth, ok := req.Header["Authorization"]
		if !ok {
			t.Errorf("Expected \"Authorization\" header, got %v", req.Header)
		}
		if len(auth) != 1 {
			t.Errorf("Expected only 1 \"Authorization\" header, got %d: %v", len(auth), req.Header)
		}
		if len(strings.Fields(auth[0])) != 2 {
			// fatal, as index-access later will likely cause a panic
			t.Fatalf("Expected exactly 2 fields in the authorization value, got %d: %v", len(strings.Fields(auth[0])), auth)
		}
		if strings.Fields(auth[0])[0] != "Bearer" {
			t.Errorf("Expected token type \"Bearer\", got \"%s\"", strings.Fields(auth[0])[0])
		}
		jwtString := strings.Fields(auth[0])[1]
		t.Logf("Got JWT: %s", jwtString)
		jwtParser := jwtv5.NewParser()
		jwt, jwtErr := jwtParser.Parse(jwtString, func(token *jwtv5.Token) (interface{}, error) {
			return []byte("TODO"), nil
		})
		if jwtErr != nil {
			t.Errorf("Could not parse JWT string: %v", jwtErr)
		}
		t.Logf("JWT: %v", jwt)
		rw.WriteHeader(http.StatusOK)
	})
	server := httptest.NewUnstartedServer(handler)
	server.Start()
	t.Logf("Test-URL: %s", server.URL)
	ctx := context.Background()
	ldapCfg := ldapAuth.CreateConfig()
	ldapCfg.Enabled = true
	ldapCfg.JwtTokenUri = server.URL + "/jwt"
	handlerAuthPlugin, err := ldapAuth.New(ctx, next, ldapCfg, "ldapAuth")
	if err != nil {
		t.Fatal(err)
	}
	handlerAuthPlugin.ServeHTTP(w, getReq)
	resp := w.Result()
	if resp.StatusCode != 200 {
		t.Errorf("Expected status code 200 from GET request, got %v", resp.Status)
	}
	server.CloseClientConnections()
	server.Close()
	mockMemcachedServer.Close()
	mockLdapServer.Close()
	wg.Wait()
}
