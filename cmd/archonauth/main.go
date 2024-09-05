//go:generate oapi-codegen -package api -generate "chi-server,models" -o ../../internal/api/api.gen.go ../../api/openapi.yaml
package main

import (
	"context"
	"log"
	"net/http"

	chi "github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	archonauth "github.com/pp23/ldapAuth/cmd/archonauth/archoauth_api"
	"github.com/pp23/ldapAuth/internal/api"
)

func NewChiRouter(authApi *archonauth.AuthAPI) chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Mount("/", api.HandlerWithOptions(authApi, api.ChiServerOptions{}))
	return r
}

func main() {
	ctx := context.Background()
	ldapAuth, err := archonauth.New(ctx, archonauth.CreateConfig())
	if err != nil {
		log.Fatal(err)
	}
	authApi := archonauth.AuthAPI{
		Auth: ldapAuth,
	}
	errServer := http.ListenAndServe(":3000", NewChiRouter(&authApi))
	if errServer != nil {
		log.Fatal(errServer)
	}
}
