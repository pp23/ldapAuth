package oauth2

import (
	"fmt"
	"net/http"
	"net/url"
)

// rfc6749 4.1.1
// response_type 		- REQUIRED. MUST be "code"
// client_id 				- REQUIRED. client identifier
// redirect_uri 		- OPTIONAL.
// scope 						- OPTIONAL. scope of the access request
// state 						- RECOMMENDED. opaque value set by client. Needs to be included in redirect of user-agent back to the client.
// code_challenge   - REQUIRED. Required as of rfc7636
// example:
// GET /authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz
//
//	&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb HTTP/1.1
//
// Host: server.example.com
// Represents an authentication code
type AuthCode struct {
	ResponseType  string
	ClientId      string
	RedirectURI   *url.URL
	Scope         string
	State         string
	CodeChallenge string
}

// Test whether this request is an auth code request
func IsAuthCodeRequest(req *http.Request) bool {
	// TODO: Consider more checks based on other parameters
	return req.FormValue("response_type") == "code"
}

// Create an AuthCode instance from a http request. Returns an error if required parameters missing.
func AuthCodeFromRequest(req *http.Request) (*AuthCode, error) {
	authCode := AuthCode{
		ResponseType:  req.FormValue("response_type"),
		ClientId:      req.FormValue("client_id"),
		RedirectURI:   nil,
		Scope:         req.FormValue("scope"),
		State:         req.FormValue("state"),
		CodeChallenge: req.FormValue("code_challenge"),
	}
	if authCode.ResponseType != "code" {
		// error. see rfc6749 4.1.2.1
		return nil, fmt.Errorf("response_type not set to 'code'")
	}
	if authCode.ClientId == "" {
		// error. see rfc6749 4.1.2.1
		// ResponseError(rw, req, redirect_uri, state, errors.New(), "client_id not set")
		return nil, fmt.Errorf("invalid_request")
	}
	if authCode.CodeChallenge == "" {
		return nil, fmt.Errorf("code_challenge required")
	}
	var err error
	// rfc6749 3.1.2.3: If client registered no redirection URI, the client MUST include a redirect_uri in the auth request
	authCode.RedirectURI, err = url.Parse(req.FormValue("redirect_uri"))
	if err != nil {
		return nil, fmt.Errorf("redirect_uri needs to be set")
	}
	return &authCode, nil
}

// Set the redirect uri. Required if no redirect uri was passed in the request.
func (authCode *AuthCode) SetRedirectURI(redirectURI *url.URL) {
	authCode.RedirectURI = redirectURI
}

// Calculates and returns the authentication code
func (authCode *AuthCode) Code() (string, error) {
	return "abc", nil // TODO
}
