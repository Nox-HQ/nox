.PHONY: build test lint run clean proto-lint proto-generate proto-breaking cover cover-html

BINARY := nox
CLI_PKG := ./cli

build:
	go build -o $(BINARY) $(CLI_PKG)

test:
	go test ./...

lint:
	golangci-lint run ./...

run: build
	./$(BINARY)

clean:
	rm -f $(BINARY)
	go clean ./...

tidy:
	go mod tidy

fmt:
	gofmt -w .
	goimports -w .

vet:
	go vet ./...

check: lint test vet

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func coverage.out

cover-html: cover
	go tool cover -html=coverage.out

proto-lint:
	cd proto && buf lint

proto-generate:
	cd proto && buf generate

proto-breaking:
	cd proto && buf breaking --against '.git#subdir=proto'
