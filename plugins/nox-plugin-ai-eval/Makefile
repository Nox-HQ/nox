PLUGIN_NAME := nox-plugin-ai-eval

.PHONY: build test lint clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(PLUGIN_NAME) .

test:
	go test ./...

lint:
	golangci-lint run

clean:
	rm -f $(PLUGIN_NAME)
