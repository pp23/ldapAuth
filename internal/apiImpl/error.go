package archonauth

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/pp23/ldapAuth/internal/ldapIdp"
	"github.com/pp23/ldapAuth/internal/utils"
)

func ResponseError(w http.ResponseWriter, req *http.Request, redirect_uri string, state string, err error, errDescr string, l *utils.Logger) {
	l.DEBUG.Println(err)
	errMsg := strings.Trim(err.Error(), "\x00")
	location, uriErr := url.Parse(redirect_uri)
	// no redirect_uri, response the error without redirect
	if uriErr != nil || location.RawPath == "" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(fmt.Sprintf("%d %s\nError: %s - %s\n", http.StatusBadRequest, http.StatusText(http.StatusBadRequest), errMsg, errDescr)))
		return
	}
	v := url.Values{}
	v.Add("error", errMsg)
	if state != "" {
		v.Add("state", state)
	}
	if errDescr != "" {
		v.Add("error_description", errDescr)
	}
	location.RawQuery = v.Encode()
	w.Header().Add("Location", location.String())
	w.WriteHeader(http.StatusTemporaryRedirect)
}

// RequireAuth set Auth request.
func RequireAuth(w http.ResponseWriter, req *http.Request, config *ldapIdp.Config, l *utils.Logger, err ...error) {
	l.DEBUG.Println(err)
	w.Header().Set("Content-Type", "text/plain")
	if config.WWWAuthenticateHeader {
		wwwHeaderContent := "Basic"
		if config.WWWAuthenticateHeaderRealm != "" {
			wwwHeaderContent = fmt.Sprintf("Basic realm=\"%s\"", config.WWWAuthenticateHeaderRealm)
		}
		w.Header().Set("WWW-Authenticate", wwwHeaderContent)
	}

	w.WriteHeader(http.StatusUnauthorized)

	errMsg := strings.Trim(err[0].Error(), "\x00")
	_, _ = w.Write([]byte(fmt.Sprintf("%d %s\nError: %s\n", http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), errMsg)))
}
