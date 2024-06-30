package oauth2

import (
	"fmt"
	"net/http"
)

// rfc6749 4.1.4 Access Token Response
// rfc6749 5.1.
// access_token  - REQUIRED.
// token_type    - REQUIRED. "bearer" or "mac" (section 7.1.).
// expires_in    - RECOMMENDED. lifetime in seconds.
// refresh_token - OPTIONAL.
// scope         - OPTIONAL, if identical to requested scope, otherwise REQUIRED.

type OpaqueToken struct {
	access_token  string
	token_type    string
	expires_in    uint64
	refresh_token string
	scope         string
}

func IsOpaqueTokenRequest(req *http.Request) bool {
	// TODO: Consider more checks based on other parameters
	return req.FormValue("grant_type") == "authorization_code"
}

// Create an OpaqueToken from HTTP request
func OpaqueTokenFromRequest(req *http.Request) (*OpaqueToken, error) {
	if req.FormValue("grant_type") != "authorization_code" {
		return nil, fmt.Errorf("invalid_request")
	}
	// TODO: invalid_client, client auth failed
	// TODO: invalid_grant, provided authorization grant invalid
	// TODO: unauthorized_client, client not authorized to use this authorization grant type
	// TODO: unsupported_grant_type, auth grant type not supported by server
	// TODO: invalid_scope, requested scope is invalid
	return &OpaqueToken{
		access_token:  "TODO",
		token_type:    "bearer",
		expires_in:    600,
		refresh_token: "TODO",
		scope:         "TODO",
	}, nil
}
