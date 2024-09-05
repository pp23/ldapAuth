// Package ldapAuth_test a test suit for ldap authentication plugin.
// nolint
package ldapAuth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/pp23/ldapAuth"
	archonauth "github.com/pp23/ldapAuth/cmd/archonauth/archoauth_api"
	"github.com/pp23/ldapAuth/cmd/archonauth/test"
)

func TestDemo(t *testing.T) {
	cfg := ldapAuth.CreateConfig()

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

func getAuthApiHandler(cfg *archonauth.Config, t *testing.T) http.Handler {
	api := test.NewAuthApi(cfg, t)
	return test.NewAuthApiHandler(api)
}

func getAccessToken(cfg *archonauth.Config, handler http.Handler, t *testing.T) string {
	return test.GetOpaqueToken(handler, cfg, t)
}

func TestJWTTokenSuccess(t *testing.T) {
	wg := sync.WaitGroup{}
	mockMemcache := test.NewMockMemCache()
	mockMemcachedServer := test.RunMockMemCacheServer(&wg, &mockMemcache, t)
	mockLdapServer := test.RunMockLdapServer(&wg, t)
	cfg := test.CreateConfig()
	handler := getAuthApiHandler(cfg, t)
	at := getAccessToken(cfg, handler, t)
	getReq := httptest.NewRequest(
		"GET",
		"http://localhost/jwt",
		nil,
	)
	t.Logf("Current Cache: %v", mockMemcache)
	getReq.Header["Authorization"] = []string{"Bearer " + at}
	w := httptest.NewRecorder()
	handler2 := getAuthApiHandler(cfg, t)
	handler2.ServeHTTP(w, getReq)
	resp := w.Result()
	if resp.StatusCode != 200 {
		t.Errorf("Expected status code 200 from GET request, got %v", resp.Status)
	}
	mockMemcachedServer.Close()
	mockLdapServer.Close()
	wg.Wait()
}
