//go:generate oapi-codegen -package api -generate "chi-server,models" -o ../../internal/api/api.gen.go ../../api/openapi.yaml
package main

import (
	"context"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"

	chi "github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	archonauth "github.com/pp23/ldapAuth/cmd/archonauth/archoauth_api"
	"github.com/pp23/ldapAuth/cmd/archonauth/config"
	"github.com/pp23/ldapAuth/internal/api"
)

const (
	ENV_CONFIG_FILE_KEY = "ARCHONAUTH_CONFIG_FILE"
	DEFAULT_CONFIG_FILE = "/etc/archonauth/config.yaml"
)

func NewChiRouter(authApi *archonauth.AuthAPI) chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Mount("/", api.HandlerWithOptions(authApi, api.ChiServerOptions{}))
	return r
}

func main() {
	ctx := context.Background()
	cfgFile, exists := os.LookupEnv(ENV_CONFIG_FILE_KEY)
	if !exists {
		log.Printf("Environment variabke %s not set. Using default config file %s", ENV_CONFIG_FILE_KEY, DEFAULT_CONFIG_FILE)
		cfgFile = DEFAULT_CONFIG_FILE
	}
	log.Printf("Config file: %s", cfgFile)
	data, fileErr := ioutil.ReadFile(cfgFile)
	if fileErr != nil {
		log.Printf("Using default configuration because config file (%s) could not be read: %v", cfgFile, fileErr)
	}
	cfg, cfgErr := config.CreateConfig().FromYaml(data)
	if cfgErr != nil {
		log.Fatalf("Could not parse config yaml file %s: %v", cfgFile, cfgErr)
	}
	ldapAuth, err := archonauth.New(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}
	authApi := archonauth.AuthAPI{
		Auth: ldapAuth,
	}
	errServer := http.ListenAndServe(cfg.Address+":"+strconv.Itoa(int(cfg.Port)), NewChiRouter(&authApi))
	if errServer != nil {
		log.Fatal(errServer)
	}
}
