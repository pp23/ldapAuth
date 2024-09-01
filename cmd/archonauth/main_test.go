package main

import (
	"context"
	"net/http/httptest"
	"os"
	"testing"
)

func TestRunServer(t *testing.T) {
	ctx := context.Background()
	ldapAuth, err := New(ctx, CreateConfig())
	if err != nil {
		LoggerERROR.Printf("%v", err)
		os.Exit(1)
	}
	authApi := AuthAPI{
		Auth: ldapAuth,
	}
	handler := NewChiRouter(&authApi)
	w := httptest.NewRecorder()
	excpectedRedirectURI := "https://localhost:1234/token"
	expectedCodeChallenge := "challenge123"
	expectedState := "123"
	req := httptest.NewRequest(
		"POST",
		"http://localhost/auth?state="+expectedState+"&redirect_uri="+excpectedRedirectURI+"&client_id=abc&response_type=code&code_challenge="+expectedCodeChallenge,
		nil,
	)
	handler.ServeHTTP(w, req)
}
