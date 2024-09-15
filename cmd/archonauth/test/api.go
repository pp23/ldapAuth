package test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	archonauth "github.com/pp23/ldapAuth/cmd/archonauth/archoauth_api"
	"github.com/pp23/ldapAuth/cmd/archonauth/config"
	"github.com/pp23/ldapAuth/internal/api"
)

func CreateConfig() *config.Config {
	return config.CreateConfig()
}

func NewAuthApi(cfg *config.Config, t *testing.T) *archonauth.AuthAPI {
	ctx := context.Background()
	// next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	cfg.Ldap.LogLevel = "DEBUG"
	cfg.Ldap.URL = "ldap://localhost"
	ldapAuth, err := archonauth.New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &archonauth.AuthAPI{
		Auth: ldapAuth,
	}
}

func NewAuthApiHandler(authApi *archonauth.AuthAPI) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Mount("/", api.HandlerWithOptions(authApi, api.ChiServerOptions{}))
	return r
}

func RunMockMemCacheServer(wg *sync.WaitGroup, mockMemcache *MockMemCache, t *testing.T) *MockTCPServer {
	mockMemcachedServer := MockTCPServer{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		mockMemcachedServer.Run(
			11211,
			mockMemcache.MockMemCachedMsgHandler,
			func(err error) { t.Error("Error: ", err) },
		)
	}()
	return &mockMemcachedServer
}

func RunMockLdapServer(wg *sync.WaitGroup, t *testing.T) *MockTCPServer {
	mockLdapServer := MockTCPServer{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		mockLdapServer.Run(
			1389,
			MockBindResponse,
			func(err error) { t.Error("Error: ", err) /* t.Error() causes the test to fail */ },
		)
	}()
	return &mockLdapServer
}

func GetOpaqueToken(handler http.Handler, cfg *config.Config, testCfg TestConfig, t *testing.T) string {
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
		"GET",
		"http://localhost/auth?state="+expectedState+"&redirect_uri="+excpectedRedirectURI+"&client_id=abc&response_type=code&code_challenge="+expectedCodeChallenge,
		nil,
	)
	w := httptest.NewRecorder()
	cfg.Ldap.LogLevel = "DEBUG"
	cfg.Ldap.URL = "ldap://localhost"
	t.Log("MockLdapServer URL: " + cfg.Ldap.URL)
	cfg.Ldap.Port = 1389
	req.SetBasicAuth(testCfg.TestUsername, testCfg.TestPassword)
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
	return resObj["access_token"].(string)
}
