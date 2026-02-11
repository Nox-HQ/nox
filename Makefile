.PHONY: build test lint run clean proto-lint proto-generate proto-breaking cover cover-html hooks

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

hooks:
	cp scripts/pre-commit .git/hooks/pre-commit
	chmod +x .git/hooks/pre-commit
	@echo "pre-commit hook installed"

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
