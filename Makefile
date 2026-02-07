.PHONY: build test lint run clean

BINARY := hardline
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
