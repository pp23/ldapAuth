.PHONY: build

export GO111MODULE=on
GOCMD=go

default: build

build: ## Build your project and put the output binary in bin/
	mkdir -p bin/
	GO111MODULE=on $(GOCMD) build -o bin/example-go-oauth2 ./
