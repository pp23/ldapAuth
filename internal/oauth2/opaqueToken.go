package oauth2

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
)

// rfc6749 4.1.3 Access Token Request
// grant_type   - REQUIRED. must be "authorization_code"
// code         - REQUIRED. authcode received from authorization server.
// redirect_uri - REQUIRED, if redirect_uri was included in auth request, value must be identical.
// client_id    - REQUIRED, if client is not authenticating with authorization server.

type OpaqueTokenRequest struct {
	GrantType   string
	Code        string
	RedirectURI *url.URL
	ClientID    string
}

// rfc6749 4.1.4 Access Token Response
// rfc6749 5.1.
// access_token  - REQUIRED.
// token_type    - REQUIRED. "bearer" or "mac" (section 7.1.).
// expires_in    - RECOMMENDED. lifetime in seconds.
// refresh_token - OPTIONAL.
// scope         - OPTIONAL, if identical to requested scope, otherwise REQUIRED.

type OpaqueToken struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    uint64 `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

func IsOpaqueTokenRequest(req *http.Request) bool {
	// TODO: Consider more checks based on other parameters
	err := req.ParseForm()
	if err != nil {
		log.Print(err)
		return false
	}
	return req.FormValue("grant_type") == "authorization_code"
}

// Create an OpaqueToken from HTTP request
func OpaqueTokenFromRequest(req *http.Request) (*OpaqueTokenRequest, error) {
	err := req.ParseForm()
	if err != nil {
		log.Print(err)
		return nil, fmt.Errorf("invalid_request")
	}
	opaqueTokenRequest := OpaqueTokenRequest{
		GrantType:   req.FormValue("grant_type"),
		Code:        req.FormValue("code"),
		RedirectURI: nil,
		ClientID:    req.FormValue("client_id"),
	}
	if opaqueTokenRequest.GrantType != "authorization_code" {
		return nil, fmt.Errorf("invalid_request")
	}

	// authentcating a webapp client which runs of the users machine:
	// intermediate client secret is encrypted in auth code
	// check client_id and decrypted client secret from auth code with cached values

	// TODO: invalid_client, client auth failed
	// TODO: invalid_grant, provided authorization grant invalid
	// TODO: unauthorized_client, client not authorized to use this authorization grant type
	// TODO: unsupported_grant_type, auth grant type not supported by server
	// TODO: invalid_scope, requested scope is invalid
	return &opaqueTokenRequest, nil
}

func (tokenRequest *OpaqueTokenRequest) AccessTokenJson() ([]byte, error) {
	token := OpaqueToken{
		AccessToken:  "TODO-UUID-OR-WHATEVER-0000000000000000000000000000000000000000",
		TokenType:    "bearer",
		ExpiresIn:    600,
		RefreshToken: "TODO",
		Scope:        "TODO",
	}
	b, err := json.Marshal(token)
	if err != nil {
		return []byte{}, err
	}
	return b, nil
}
