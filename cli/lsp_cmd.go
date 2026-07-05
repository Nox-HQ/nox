package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/nox-hq/nox/cli/lsp"
)

// runLSP starts the nox Language Server over stdio. It speaks JSON-RPC 2.0 and
// publishes nox findings as editor diagnostics on didOpen/didSave. It takes no
// positional arguments; unknown flags cause a usage error.
func runLSP(args []string) int {
	fs := flag.NewFlagSet("lsp", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: nox lsp")
		fmt.Fprintln(os.Stderr, "\nRun the nox Language Server on stdio (JSON-RPC 2.0).")
		fmt.Fprintln(os.Stderr, "Editors connect to publish nox findings as diagnostics.")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	srv := lsp.NewServer(os.Stdin, os.Stdout, version)
	if err := srv.Serve(); err != nil {
		fmt.Fprintf(os.Stderr, "nox lsp: %v\n", err)
		return 1
	}
	return 0
}
