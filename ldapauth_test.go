// Package ldapAuth_test a test suit for ldap authentication plugin.
//nolint
package ldapAuth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pp23/ldapAuth"
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
