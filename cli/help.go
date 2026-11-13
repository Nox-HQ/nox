package cli

import (
	"fmt"
	"os"
)

// isHelpArg reports whether a is a request for a command's usage.
func isHelpArg(a string) bool {
	switch a {
	case "-h", "-help", "--help", "help":
		return true
	}
	return false
}

// printGroupHelp answers a request for help on a command that dispatches on
// its first argument: the usage goes to stdout and the exit code is 0, because
// the user asked for it and got it.
//
// Eight such commands had no flag set of their own, so `nox baseline --help`
// reached the subcommand switch and was reported as "unknown baseline
// subcommand: --help", exit 2: the request for help answered as a mistake.
func printGroupHelp(usage string) int {
	_, _ = fmt.Fprintln(os.Stdout, usage)
	return 0
}
