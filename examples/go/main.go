package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/oauth2"
)

func main() {
	ctx := context.Background()

	clientSecret, ok := os.LookupEnv("CLIENT_SECRET")
	if !ok {
		log.Fatal("No CLIENT_SECRET environment variable set")
	}
	conf := oauth2.Config{
		ClientID:     "clientid",
		ClientSecret: clientSecret,
		Scopes:       []string{""},
		Endpoint: oauth2.Endpoint{
			TokenURL: "http://localhost:3000/token",
			AuthURL:  "http://localhost:3000/auth",
		},
	}

	url := conf.AuthCodeURL("state", oauth2.AccessTypeOffline)
	log.Printf("Visit %s", url)

	var code string
	fmt.Print("AuthCode: ")
	if _, err := fmt.Scanf("%s", &code); err != nil {
		log.Fatal(err)
	}

	httpClient := &http.Client{Timeout: 2 * time.Second}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	token, err := conf.Exchange(ctx, code)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Token: %s", token)

	client := conf.Client(ctx, token)
	_ = client

	ctx.Done()
}
