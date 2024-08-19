// Package ldapAuth_test a test suit for ldap authentication plugin.
// nolint
package ldapAuth_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	jwtv5 "github.com/golang-jwt/jwt/v5"
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

// partly copied from https://github.com/bradfitz/gomemcache
type serverItem struct {
	flags   uint32
	data    []byte
	exp     time.Time // or zero value for no expiry
	casUniq uint64
}

// global cache
var mockMemcache map[string]serverItem

func mockMemCachedMsgHandler(br *bufio.Reader, bw *bufio.Writer) error {
	writeRx := regexp.MustCompile(`^(set|add|replace|append|prepend|cas) (\S+) (\d+) (\d+) (\d+)(?: (\S+))?( noreply)?\r\n`)
	for {
		b, err := br.ReadSlice('\n')
		if err != nil {
			fmt.Printf("Read from connection: %v\r\n", err)
			return nil
		}
		line := string(b)
		fmt.Printf("string: %s", line)
		fmt.Printf("bytes2hex: %s", bytesToHexString(b))

		if strings.HasPrefix(line, "gets") {
			key := strings.Fields(strings.TrimPrefix(line, "gets "))[0]
			fmt.Printf("%s: [%s]", "gets", key)
			if val, ok := mockMemcache[key]; ok {
				fmt.Printf("%s: [%s]: %s", "gets", key, bytesToHexString(val.data))
				fmt.Fprintf(bw, "VALUE %s %d %d %d\r\n", key, val.flags, len(val.data), val.casUniq)
				bw.Write(val.data)
				bw.Write([]byte("\r\n"))
				bw.Write([]byte("END\r\n"))
				bw.Flush()
			} else {
				fmt.Printf("Key not found: %s. Current cache: %v", key, mockMemcache)
				for k := range mockMemcache {
					fmt.Printf("%s == %s : %v", key, k, key == k)
				}
			}
			continue
		}
		if m := writeRx.FindStringSubmatch(line); m != nil {
			verb, key, flagsStr, exptimeStr, lenStr, casUniq, noReply := m[1], m[2], m[3], m[4], m[5], m[6], strings.TrimSpace(m[7])
			flags, _ := strconv.ParseUint(flagsStr, 10, 32)
			exptimeVal, _ := strconv.ParseInt(exptimeStr, 10, 64)
			itemLen, _ := strconv.ParseInt(lenStr, 10, 32)
			fmt.Printf("got %q flags=%q exp=%d %d len=%d cas=%q noreply=%q", verb, key, flags, exptimeVal, itemLen, casUniq, noReply)
			body := make([]byte, itemLen+2)
			_, err := io.ReadFull(br, body)
			if err != nil {
				fmt.Printf("Could not read message body: %v", err)
				return err
			}
			fmt.Printf("body: %s", bytesToHexString(body[:itemLen]))
			mockMemcache[key] = serverItem{
				flags:   uint32(flags),
				data:    body[:itemLen],
				casUniq: 1,
				exp:     time.Unix(exptimeVal, 0),
			}
			fmt.Printf("%s: [%s]: %v (%s)", verb, key, body, string(body))
			bw.Write([]byte("STORED\r\n"))
			bw.Flush()
			continue
		}
		fmt.Printf("Unknown memcached command: %s", line)
	}
}

type MockTCPServer struct {
	hostport string
	l        net.Listener
	conns    []net.Conn
	stop     bool
}

type TesTCPPServer interface {
	Run(
		port uint16,
		msgHandler func(br *bufio.Reader, bw *bufio.Writer),
		errHandler func(error),
	) error
	Close()
}

func (mockTcpServer *MockTCPServer) Run(
	port uint16,
	msgHandler func(br *bufio.Reader, bw *bufio.Writer) error,
	errHandler func(error),
) error {
	mockTcpServer.stop = false
	mockTcpServer.hostport = ":" + strconv.Itoa(int(port))
	l, err := net.Listen("tcp", mockTcpServer.hostport)
	if err != nil {
		errHandler(err)
		return err
	}
	mockTcpServer.l = l
	for !mockTcpServer.stop {
		conn, err := l.Accept()
		if err != nil {
			// check if server was stopped anyway (the error resulted likely from a use of closed network connection)
			if mockTcpServer.stop {
				// errHandler(err) // usually not an error
				break
			}
			errHandler(err)
			continue
		}
		fmt.Printf("New connection: %s", conn.RemoteAddr())
		mockTcpServer.conns = append(mockTcpServer.conns, conn)
		defer conn.Close()
		br := bufio.NewReader(conn)
		bw := bufio.NewWriter(conn)
		msgErr := msgHandler(br, bw)
		if msgErr != nil {
			if !errors.Is(msgErr, io.EOF) {
				fmt.Printf("msgHandler error %v", msgErr)
				errHandler(msgErr)
			} else {
				fmt.Printf("Ignoring error %v", msgErr)
			}
		}
		conn.Close()
	}
	return nil
}

func (mockTcpServer *MockTCPServer) Close() {
	mockTcpServer.stop = true
	if mockTcpServer.l == nil {
		fmt.Printf("Listener was already nil of %s", mockTcpServer.hostport)
	} else {
		mockTcpServer.l.Close()
	}
	for _, c := range mockTcpServer.conns {
		c.Close()
	}
}

func mockBindResponse(br *bufio.Reader, bw *bufio.Writer) error {
	// build the LDAP Bind Response packet
	pkt := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 1, nil, "Bind Response")
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "resultCode"))
	pkt.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagUTF8String, "cn=user02", "matchedDN"))
	pkt.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagUTF8String, "test", "diagnosticMessage"))
	envelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	envelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "MessageID"))
	envelope.AppendChild(pkt)

	bw.Write(envelope.Bytes())
	bw.Flush()
	return nil
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
	mockMemcachedServer := MockTCPServer{}
	wg := sync.WaitGroup{}
	wg.Add(2)
	// memcachedServer
	t.Log("Start MockMemcachedServer")
	mockMemcache = make(map[string]serverItem)
	go func() {
		defer wg.Done()
		mockMemcachedServer.Run(
			11211,
			mockMemCachedMsgHandler,
			func(err error) { t.Error("Error: ", err) },
		)
	}()
	// LDAPServer
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
	cfg := ldapIdp.CreateConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	cfg.LogLevel = "DEBUG"
	cfg.URL = "ldap://localhost"
	t.Log("MockLdapServer URL: " + cfg.URL)
	mockLdapServer := MockTCPServer{}
	mockMemcachedServer := MockTCPServer{}
	wg := sync.WaitGroup{}
	wg.Add(2)
	// memcachedServer
	mockMemcache = make(map[string]serverItem)
	go func() {
		defer wg.Done()
		mockMemcachedServer.Run(
			11211,
			mockMemCachedMsgHandler,
			func(err error) { t.Error("Error: ", err) },
		)
	}()
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
	t.Logf("AuthCode: %s", authCode)
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
			t.Errorf("Expected exactly 2 fields in the authorization value, got %d: %v", len(strings.Fields(auth[0])), auth)
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
	cfg.LogLevel = "DEBUG"
	cfg.URL = "ldap://localhost"
	t.Log("MockLdapServer URL: " + cfg.URL)
	mockLdapServer := MockTCPServer{}
	mockMemcachedServer := MockTCPServer{}
	wg := sync.WaitGroup{}
	wg.Add(2)
	// memcachedServer
	mockMemcache = make(map[string]serverItem)
	go func() {
		defer wg.Done()
		mockMemcachedServer.Run(
			11211,
			mockMemCachedMsgHandler,
			func(err error) { t.Error("Error: ", err) },
		)
	}()
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
		"POST",
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
			"http://localhost/data",
			nil,
		)
		getReq.Header["Authorization"] = []string{"Bearer " + at.(string)}
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, getReq)
		resp := w.Result()
		if resp.StatusCode != 200 {
			t.Errorf("Expected status code 200 from GET request, got %v", resp.Status)
		}
	}
	mockMemcachedServer.Close()
	mockLdapServer.Close()
	wg.Wait()
}
