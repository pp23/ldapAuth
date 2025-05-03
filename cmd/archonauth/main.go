//go:generate oapi-codegen -package api -generate "chi-server,models" -o ../../internal/api/api.gen.go ../../api/openapi.yaml
package main

import (
	"context"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"

	archonauth "github.com/pp23/ldapAuth/internal/apiImpl"
	"github.com/pp23/ldapAuth/internal/config"
	"github.com/pp23/ldapAuth/internal/server"
	"github.com/pp23/ldapAuth/internal/utils"
)

const (
	ENV_CONFIG_FILE_KEY = "ARCHONAUTH_CONFIG_FILE"
	DEFAULT_CONFIG_FILE = "/etc/archonauth/config.yaml"
)

// Calls close and prints out all errors that occurred
func finalClose(ldapAuth *archonauth.LdapAuth, log *utils.Logger) {
	errs := ldapAuth.Close()
	for err := range errs {
		log.ERROR.Printf("ERROR: Archonauth could not be shut down cleanly: %v", err)
	}
}

func main() {
	ctx := context.Background()
	logger := utils.NewLogger()
	cfgFile, exists := os.LookupEnv(ENV_CONFIG_FILE_KEY)
	if !exists {
		logger.ERROR.Printf("Environment variable %s not set. Using default config file %s", ENV_CONFIG_FILE_KEY, DEFAULT_CONFIG_FILE)
		cfgFile = DEFAULT_CONFIG_FILE
	}
	logger.DEBUG.Printf("Config file: %s", cfgFile)
	data, fileErr := ioutil.ReadFile(cfgFile)
	if fileErr != nil {
		// actually no error, only info that default config gets used
		logger.INFO.Printf("Using default configuration because config file (%s) could not be read: %v", cfgFile, fileErr)
	}
	cfg, cfgErr := config.CreateConfig().FromYaml(data)
	if cfgErr != nil {
		log.Fatalf("Could not parse config yaml file %s: %v", cfgFile, cfgErr)
	}
	logger.SetLevel(cfg.Ldap.LogLevel)
	config.LogConfigParams(cfg, logger)
	ldapAuth, err := archonauth.New(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer finalClose(ldapAuth, logger)
	authApi, errApi := server.NewAuthApi(ldapAuth, logger, cfg)
	if errApi != nil {
		finalClose(ldapAuth, logger)
		log.Fatal(errApi)
	}
	logger.INFO.Printf("Starting server on %s:%d", cfg.Address, cfg.Port)
	errServer := http.ListenAndServe(cfg.Address+":"+strconv.Itoa(int(cfg.Port)), server.NewChiRouter(authApi))
	if errServer != nil {
		finalClose(ldapAuth, logger)
		log.Fatal(errServer)
	}
}
