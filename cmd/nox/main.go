// Command nox is the nox security scanner.
//
// Install it with:
//
//	go install github.com/nox-hq/nox/cmd/nox@latest
package main

import (
	"os"

	"github.com/nox-hq/nox/cli"
)

// Stamped by release builds with -ldflags "-X main.version=…".
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	os.Exit(cli.Main(cli.Build{Version: version, Commit: commit, Date: date}, os.Args[1:]))
}
