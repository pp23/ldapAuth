package archonauth_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/pp23/ldapAuth/internal/server"
	"github.com/pp23/ldapAuth/internal/test"
)

// global cache
var mockMemcache test.MockMemCache = test.NewMockMemCache()

// requests GET /auth without any parameters
// expectation: 401 response
func TestAuthCodeGet1ResponseUnauthorized(t *testing.T) {
	testCfg, testCfgErr := test.TestConfigFromEnv()
	if testCfgErr != nil {
		t.Fatal(testCfgErr)
	}
	cfg := test.CreateConfig()
	authApi := test.NewAuthApi(cfg, t)
	handler := server.NewChiRouter(authApi)

	expectedResCode := http.StatusUnauthorized
	req := httptest.NewRequest(
		"GET",
		"http://localhost/auth",
		nil,
	)
	w := httptest.NewRecorder()
	// mock servers should not get called, but avoid 401 responses because they are missing
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
	defer func() {
		time.Sleep(1 * time.Second) // workaround to wait until server got started so that it can get properly closed
		mockMemcachedServer.Close()
		mockLdapServer.Close()
		wg.Wait()
	}()
	cfg.Ldap.Port = 1389
	req.SetBasicAuth(testCfg.TestUsername, testCfg.TestPassword) // password gets not checked as we mock the ldap server which accepts every user
	handler.ServeHTTP(w, req)                                    // request an auth code. The user auth is done against the mocked ldap server
	resp := w.Result()
	t.Log(resp.StatusCode)
	// auth code reponse test
	if resp.StatusCode != expectedResCode {
		t.Fatalf("Expected status code %v, got %v", expectedResCode, resp.StatusCode)
	}
	_, err := resp.Location()
	if err == nil {
		t.Fatal("Location header in response. Expected none.")
	}
	// TODO: body shall show "Bad request" error
	// respBody, err := io.ReadAll(resp.Body)
	// if err != nil {
	// 	t.Fatal("Error while reading body: ", err)
	// }
	// if len(respBody) != 0 {
	// 	t.Fatalf("Expected no body, got %s [%v]", string(respBody), len(respBody))
	// }
}

func TestAuthCodeResponseSuccess(t *testing.T) {
	testCfg, testCfgErr := test.TestConfigFromEnv()
	if testCfgErr != nil {
		t.Fatal(testCfgErr)
	}
	cfg := test.CreateConfig()
	authApi := test.NewAuthApi(cfg, t)
	handler := server.NewChiRouter(authApi)

	excpectedRedirectURI := "https://localhost:1234/token"
	expectedCodeChallenge := "challenge123"
	expectedState := "123"
	req := httptest.NewRequest(
		"GET",
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
	defer func() {
		mockMemcachedServer.Close()
		mockLdapServer.Close()
		wg.Wait()
	}()
	cfg.Ldap.Port = 1389
	req.SetBasicAuth(testCfg.TestUsername, testCfg.TestPassword) // password gets not checked as we mock the ldap server which accepts every user
	handler.ServeHTTP(w, req)                                    // request an auth code. The user auth is done against the mocked ldap server
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
}
