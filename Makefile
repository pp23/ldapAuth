.PHONY: lint test vendor clean

export GO111MODULE=on
GOCMD=go

default: lint build test

lint:
	golangci-lint run

generate-api: ## Generate the REST API from OpenAPIv3 specification in api/
	@mkdir -p internal/api
	go generate ./...

build: generate-api ## Build your project and put the output binary in out/bin/
	mkdir -p out/bin
	GO111MODULE=on $(GOCMD) build -o out/bin/ ./cmd/archonauth

test:
	go test -v -cover ./...

yaegi_test:
	yaegi test -v .

vendor:
	go mod vendor

clean:
	rm -rf ./vendor
