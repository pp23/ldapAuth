// Package ldapAuth_test a test suit for ldap authentication plugin.
// nolint
package ldapAuth_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/pp23/ldapAuth"
	"github.com/pp23/ldapAuth/internal/ldapIdp"
)

func TestDemo(t *testing.T) {
	cfg := ldapIdp.CreateConfig()

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

type (
	LDAPString []byte
	LDAPDN     LDAPString
)

type LDAPResult struct {
	ResultCode        int
	MatchedDN         LDAPDN
	DiagnosticMessage LDAPString
}

func bytesToHexString(bytes []byte) string {
	if len(bytes) <= 0 {
		return ""
	}
	buf := new(strings.Builder)
	ber.PrintBytes(buf, bytes, " ")
	return buf.String()
}

type MockTCPServer struct {
	l     net.Listener
	conns []net.Conn
	stop  bool
}

type TesTCPPServer interface {
	Run(port uint16, msgHandler func(bytes []byte, conn net.Conn), errHandler func(error)) error
	Close()
}

func (ldapServer *MockTCPServer) Run(port uint16, msgHandler func(bytes []byte, conn net.Conn), errHandler func(error)) error {
	ldapServer.stop = false
	l, err := net.Listen("tcp", ":1389")
	if err != nil {
		return err
	}
	ldapServer.l = l
	for !ldapServer.stop {
		conn, err := l.Accept()
		if err != nil {
			// check if server was stopped anyway (the error resulted likely from a use of closed network connection)
			if ldapServer.stop {
				break
			}
			errHandler(err)
			continue
		}
		ldapServer.conns = append(ldapServer.conns, conn)
		defer conn.Close()
		b := make([]byte, 1024)
		n := 1
		for n > 0 {
			n, err = conn.Read(b)
			if err != nil {
				if err == io.EOF {
					break
				}
				errHandler(err)
				continue
			}
			msgHandler(b, conn)
		}
	}
	return nil
}

func (ldapServer *MockTCPServer) Close() {
	ldapServer.stop = true
	ldapServer.l.Close()
	for _, c := range ldapServer.conns {
		c.Close()
	}
}

func mockBindResponse(bytes []byte, conn net.Conn) {
	// build the LDAP Bind Response packet
	pkt := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 1, nil, "Bind Response")
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "resultCode"))
	pkt.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagUTF8String, "cn=user02", "matchedDN"))
	pkt.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagUTF8String, "test", "diagnosticMessage"))
	envelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	envelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "MessageID"))
	envelope.AppendChild(pkt)

	conn.Write(envelope.Bytes())
}

func TestAuthCodeResponseSuccess(t *testing.T) {
	excpectedRedirectURI := "https://localhost:1234/token"
	expectedCodeChallenge := "challenge123"
	expectedState := "123"
	req := httptest.NewRequest(
		"POST",
		"http://localhost/auth?state="+expectedState+"&redirect_uri="+excpectedRedirectURI+"&client_id=abc&response_type=code&code_challenge="+expectedCodeChallenge,
		nil,
	)
	w := httptest.NewRecorder()
	cfg := ldapIdp.CreateConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	cfg.LogLevel = "DEBUG"
	cfg.URL = "ldap://localhost"
	t.Log("MockLdapServer URL: " + cfg.URL)
	mockLdapServer := MockTCPServer{}
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		mockLdapServer.Run(
			1389,
			mockBindResponse,
			func(err error) { t.Error("Error: ", err) /* t.Error() causes the test to fail */ },
		)
	}()
	cfg.Port = 1389
	handler, err := ldapAuth.New(ctx, next, cfg, "ldapAuth")
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("user02", "secret")
	handler.ServeHTTP(w, req)
	resp := w.Result()
	t.Log(resp.StatusCode)
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
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal("Error while reading body: ", err)
	}
	if len(respBody) != 0 {
		t.Fatalf("Expected no body, got %s [%v]", string(respBody), len(respBody))
	}
	mockLdapServer.Close()
	wg.Wait()
}

func TestTokenResponseSuccess(t *testing.T) {
	expectedHeaders := map[string]string{
		"Content-Type": "application/json",
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
	cfg := ldapIdp.CreateConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	cfg.LogLevel = "DEBUG"
	cfg.URL = "ldap://localhost"
	t.Log("MockLdapServer URL: " + cfg.URL)
	mockLdapServer := MockTCPServer{}
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		mockLdapServer.Run(
			1389,
			mockBindResponse,
			func(err error) { t.Error("Error: ", err) /* t.Error() causes the test to fail */ },
		)
	}()
	cfg.Port = 1389
	handler, err := ldapAuth.New(ctx, next, cfg, "ldapAuth")
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("user02", "secret")
	handler.ServeHTTP(w, req)
	resp := w.Result()
	locationURL, err := resp.Location()
	if err != nil {
		t.Fatal(err)
	}
	authCode := locationURL.Query().Get("code")
	locationURL.RawFragment = ""
	locationURL.RawQuery = "" // no query in token request url, but in the body
	reqBodyValues := url.Values{}
	reqBodyValues.Add("grant_type", "authorization_code")
	reqBodyValues.Add("code", authCode)
	reqBodyValues.Add("redirect_uri", excpectedRedirectURI)
	reqBodyValues.Add("client_id", "abc") // required, if the client is not authenticating with the authorization server
	reqRedirect := httptest.NewRequest(
		"POST",
		locationURL.String(),
		strings.NewReader(reqBodyValues.Encode()),
	)
	b, _ := io.ReadAll(reqRedirect.Body)
	t.Log(string(b))
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
	mockLdapServer.Close()
	wg.Wait()
}
