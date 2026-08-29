package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/intel"
)

func runIntel(args []string) int {
	if len(args) == 0 {
		printIntelUsage()
		return 2
	}
	switch args[0] {
	case "allowlist":
		return runIntelAllowlist()
	case "preview":
		return runIntelPreview(args[1:])
	case "id":
		return runIntelID()
	case "login":
		return runIntelLogin(args[1:])
	case "logout":
		return runIntelLogout(args[1:])
	case "whoami":
		return runIntelWhoami(args[1:])
	case "register":
		return runIntelSignup(args[1:])
	case "add-operator":
		return runIntelRegister(args[1:])
	case "invite":
		return runIntelInvite(args[1:])
	case "enroll":
		return runIntelEnroll(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "nox intel: unknown subcommand %q\n\n", args[0])
		printIntelUsage()
		return 2
	}
}

func printIntelUsage() {
	fmt.Fprintf(os.Stderr, "Usage: nox intel <command>\n\n")
	fmt.Fprintf(os.Stderr, "  allowlist        print every field an observation may carry\n")
	fmt.Fprintf(os.Stderr, "  preview <path>   show exactly what a scan of <path> would contribute\n")
	fmt.Fprintf(os.Stderr, "  id               print this installation's opaque reporter id\n")
	fmt.Fprintf(os.Stderr, "\nOperator accounts:\n")
	fmt.Fprintf(os.Stderr, "  login            approve this terminal from your browser and store the session\n")
	fmt.Fprintf(os.Stderr, "  logout           revoke the session, on the server as well as here\n")
	fmt.Fprintf(os.Stderr, "  whoami           show who this machine is signed in as\n")
	fmt.Fprintf(os.Stderr, "  register         open the web page where an organisation is created\n")
	fmt.Fprintf(os.Stderr, "  add-operator     add someone to your organisation and print their link\n")
	fmt.Fprintf(os.Stderr, "  invite           re-issue an enrolment link that expired\n")
	fmt.Fprintf(os.Stderr, "  enroll           bind an authenticator using an enrolment link\n\n")
	fmt.Fprintf(os.Stderr, "Contribution is off unless scan.intelligence.contribute is set,\n")
	fmt.Fprintf(os.Stderr, "and is a separate decision from querying an intelligence endpoint.\n")
}

// runIntelAllowlist prints the allowlist. The design requires that "what would
// you send?" be answerable without reading the source; this is that answer.
func runIntelAllowlist() int {
	if err := intel.PrintAllowlist(os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "nox intel: %v\n", err)
		return 1
	}
	return 0
}

// runIntelPreview scans a target and prints the observations it would
// contribute, without contributing them.
//
// An allowlist describes the shape of what leaves. This shows the actual
// values, derived from the operator's own repository, which is the only way to
// check the claim against a codebase rather than against a promise.
func runIntelPreview(args []string) int {
	target := "."
	if len(args) > 0 {
		target = args[0]
	}

	result, err := core.RunScanWithOptions(target, core.ScanOptions{ToolVersion: version})
	if err != nil {
		fmt.Fprintf(os.Stderr, "nox intel preview: %v\n", err)
		return 1
	}

	reporterID, err := intel.ReporterID("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "nox intel preview: %v\n", err)
		return 1
	}

	obs := intel.Derive(result.Findings.Findings(), intel.DeriveOptions{
		ReporterID:  reporterID,
		ObservedAt:  time.Now().UTC().Format(time.RFC3339),
		ToolVersion: version,
	})

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(obs); err != nil {
		fmt.Fprintf(os.Stderr, "nox intel preview: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stderr, "\n%d observation(s) from %d finding(s). Nothing was sent.\n",
		len(obs), len(result.Findings.Findings()))
	return 0
}

func runIntelID() int {
	id, err := intel.ReporterID("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "nox intel id: %v\n", err)
		return 1
	}
	fmt.Println(id)
	fmt.Fprintf(os.Stderr, "\nDerived from a private salt at %s, which never leaves this machine.\n",
		intel.DefaultSaltPath())
	return 0
}
