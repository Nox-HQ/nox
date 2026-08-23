package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/mcpdrift"
	"github.com/nox-hq/nox/core/report"
	"github.com/nox-hq/nox/core/report/sarif"
)

// mcpUsage is the shared usage banner for the `nox mcp` command family.
const mcpUsage = `Usage: nox mcp <baseline|drift|show> [flags] -- <server-launch-command...>

Capture a reviewable baseline of an MCP server's tool manifest and detect drift
(a "rug-pull": a server that shows a benign manifest at review time, then serves
a changed or malicious one later). The baseline is local, diffable JSON —
commit it, review it in PRs, and treat drift as a finding.

Subcommands:
  baseline   Capture the server's tool manifest into .nox/mcp-baseline.json
  drift      Re-capture and report drift against the baseline (emits findings)
  show       Print the stored baseline summary

Flags:
  --baseline <path>   baseline file (default: .nox/mcp-baseline.json)
  --output <dir>      directory for findings.json / results.sarif (drift only; default: .)
  --timeout <dur>     per-request timeout (default: 15s)
  --force             overwrite an existing baseline (baseline only)

SECURITY — READ BEFORE RUNNING UNTRUSTED SERVERS:
  This command LAUNCHES the server command you pass as a subprocess and speaks
  MCP to it. A malicious MCP server can open network sockets, read your files,
  or tamper with the host the moment it starts. NEVER run an untrusted server
  with this command directly on your machine. Run it inside an isolated
  sandbox with no network and a read-only filesystem, e.g.:

    docker run --rm -i --network none --read-only --cap-drop ALL \
      untrusted/mcp-server | nox mcp baseline -- <containerized launch>

  nox does not sandbox the subprocess for you; isolation is your
  responsibility. Baselining a server you already trust (e.g. "nox serve") is
  safe.

Examples:
  nox mcp baseline -- nox serve
  nox mcp drift -- nox serve
  nox mcp drift --output ci-reports -- ./my-mcp-server --stdio
`

func runMCP(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, mcpUsage)
		return 2
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "baseline":
		return mcpBaseline(rest)
	case "drift":
		return mcpDrift(rest)
	case "show":
		return mcpShow(rest)
	case "-h", "--help", "help":
		fmt.Print(mcpUsage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown mcp subcommand: %s\n\n", sub)
		fmt.Fprint(os.Stderr, mcpUsage)
		return 2
	}
}

// splitServerCommand separates our own flags from the server launch command.
// The convention is `nox mcp <sub> [our flags] -- <server cmd...>`. If no `--`
// is present, everything is passed to flag parsing and the leftover positional
// args are treated as the server command.
func splitServerCommand(args []string) (ourArgs, serverCmd []string) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

func mcpBaseline(args []string) int {
	ourArgs, serverCmd := splitServerCommand(args)
	fs := flag.NewFlagSet("mcp baseline", flag.ContinueOnError)
	var baselinePath, target string
	var timeout time.Duration
	var force bool
	fs.StringVar(&baselinePath, "baseline", "", "baseline file path (default: .nox/mcp-baseline.json)")
	fs.StringVar(&target, "target", ".", "project root for the default baseline path")
	fs.DurationVar(&timeout, "timeout", 15*time.Second, "per-request timeout")
	fs.BoolVar(&force, "force", false, "overwrite an existing baseline")
	if err := fs.Parse(ourArgs); err != nil {
		return 2
	}
	if len(serverCmd) == 0 {
		serverCmd = fs.Args()
	}
	if len(serverCmd) == 0 {
		fmt.Fprintln(os.Stderr, "error: no server command given. Use: nox mcp baseline -- <server cmd...>")
		return 2
	}
	if baselinePath == "" {
		baselinePath = mcpdrift.DefaultPath(target)
	}

	if !force {
		if _, err := os.Stat(baselinePath); err == nil {
			fmt.Fprintf(os.Stderr, "baseline already exists at %s — re-run with --force to overwrite, or use `nox mcp drift` to check it.\n", baselinePath)
			return 2
		}
	}

	printSandboxWarning(serverCmd)

	m, err := mcpdrift.CaptureManifest(context.Background(), mcpdrift.CaptureOptions{Command: serverCmd, Timeout: timeout})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: capturing MCP manifest: %v\n", err)
		return 2
	}

	bl := mcpdrift.NewBaseline(serverCmd, m, time.Now())
	if err := bl.Save(baselinePath); err != nil {
		fmt.Fprintf(os.Stderr, "error: writing baseline: %v\n", err)
		return 2
	}

	fmt.Printf("mcp baseline: captured %d tools from %q (fingerprint %s) -> %s\n",
		len(m.Tools), m.ServerName, bl.Meta.Fingerprint, baselinePath)
	fmt.Println("Commit this file. Review it in PRs. Run `nox mcp drift` in CI to catch a rug-pull.")
	return 0
}

func mcpShow(args []string) int {
	ourArgs, _ := splitServerCommand(args)
	fs := flag.NewFlagSet("mcp show", flag.ContinueOnError)
	var baselinePath, target string
	fs.StringVar(&baselinePath, "baseline", "", "baseline file path (default: .nox/mcp-baseline.json)")
	fs.StringVar(&target, "target", ".", "project root for the default baseline path")
	if err := fs.Parse(ourArgs); err != nil {
		return 2
	}
	if baselinePath == "" {
		baselinePath = mcpdrift.DefaultPath(target)
	}
	bl, err := mcpdrift.Load(baselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading baseline: %v\n", err)
		return 2
	}
	fmt.Printf("mcp baseline: %s\n", baselinePath)
	fmt.Printf("  server      : %s %s (protocol %s)\n", bl.Manifest.ServerName, bl.Manifest.ServerVersion, bl.Manifest.ProtocolVersion)
	fmt.Printf("  command     : %v\n", bl.Meta.Command)
	fmt.Printf("  captured    : %s\n", bl.Meta.CapturedAt.Format(time.RFC3339))
	fmt.Printf("  fingerprint : %s\n", bl.Meta.Fingerprint)
	fmt.Printf("  tools (%d):\n", len(bl.Manifest.Tools))
	for i := range bl.Manifest.Tools {
		fmt.Printf("    - %s\n", bl.Manifest.Tools[i].Name)
	}
	return 0
}

func mcpDrift(args []string) int {
	ourArgs, serverCmd := splitServerCommand(args)
	fs := flag.NewFlagSet("mcp drift", flag.ContinueOnError)
	var baselinePath, target, outputDir string
	var timeout time.Duration
	fs.StringVar(&baselinePath, "baseline", "", "baseline file path (default: .nox/mcp-baseline.json)")
	fs.StringVar(&target, "target", ".", "project root for the default baseline path")
	fs.StringVar(&outputDir, "output", ".", "directory for findings.json / results.sarif")
	fs.DurationVar(&timeout, "timeout", 15*time.Second, "per-request timeout")
	if err := fs.Parse(ourArgs); err != nil {
		return 2
	}
	if len(serverCmd) == 0 {
		serverCmd = fs.Args()
	}
	if baselinePath == "" {
		baselinePath = mcpdrift.DefaultPath(target)
	}

	bl, err := mcpdrift.Load(baselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading baseline: %v\n", err)
		fmt.Fprintln(os.Stderr, "Capture one first with: nox mcp baseline -- <server cmd...>")
		return 2
	}
	// Default to the command recorded in the baseline so `nox mcp drift` needs no
	// arguments in CI once a baseline exists.
	if len(serverCmd) == 0 {
		serverCmd = bl.Meta.Command
	}
	if len(serverCmd) == 0 {
		fmt.Fprintln(os.Stderr, "error: no server command and none recorded in the baseline.")
		return 2
	}

	printSandboxWarning(serverCmd)

	current, err := mcpdrift.CaptureManifest(context.Background(), mcpdrift.CaptureOptions{Command: serverCmd, Timeout: timeout})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: capturing MCP manifest: %v\n", err)
		return 2
	}

	diff := mcpdrift.DiffManifests(bl.Manifest, current)
	server := bl.Manifest.ServerName
	if server == "" {
		server = current.ServerName
	}
	drift := mcpdrift.ToFindings(diff, baselinePath, server)

	// Flow drift through the normal findings/report path: build a FindingSet and
	// emit findings.json + results.sarif exactly like a scan.
	fsSet := findings.NewFindingSet()
	for i := range drift {
		fsSet.Add(drift[i])
	}
	fsSet.Deduplicate()

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error: creating output directory: %v\n", err)
		return 2
	}
	jsonPath := filepath.Join(outputDir, "findings.json")
	// no degradations: every failure above — an unreadable baseline, a manifest
	// that could not be captured — exits 2 rather than continuing, so this
	// command has no partial-result state to report.
	if err := report.NewJSONReporter(version).WriteToFile(fsSet, jsonPath); err != nil {
		fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", jsonPath, err)
		return 2
	}
	sarifPath := filepath.Join(outputDir, "results.sarif")
	if err := sarif.NewReporter(version, nil).WriteToFile(fsSet, sarifPath); err != nil {
		fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", sarifPath, err)
		return 2
	}

	printDriftReport(diff, drift, server, baselinePath, jsonPath, sarifPath)

	if diff.IsDrift() {
		return 1 // drift is a gate failure, like new findings in a scan
	}
	return 0
}

// printDriftReport renders a deterministic human summary of the drift.
func printDriftReport(diff mcpdrift.Diff, drift []findings.Finding, server, baselinePath, jsonPath, sarifPath string) {
	if !diff.IsDrift() {
		fmt.Printf("mcp drift: no drift — %s matches the baseline (%s).\n", server, baselinePath)
		fmt.Printf("  wrote %s, %s\n", jsonPath, sarifPath)
		return
	}
	fmt.Printf("mcp drift: DRIFT DETECTED on %s vs baseline %s\n", server, baselinePath)

	// Count by severity for the headline.
	sev := map[findings.Severity]int{}
	for i := range drift {
		sev[drift[i].Severity]++
	}
	fmt.Printf("  %d finding(s): %s\n", len(drift), severityLine(sev))

	sorted := make([]findings.Finding, len(drift))
	copy(sorted, drift)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].RuleID != sorted[j].RuleID {
			return sorted[i].RuleID < sorted[j].RuleID
		}
		return sorted[i].Metadata["tool"] < sorted[j].Metadata["tool"]
	})
	for i := range sorted {
		f := sorted[i]
		fmt.Printf("  [%-8s] %s  %s\n", f.Severity, f.RuleID, f.Message)
	}
	fmt.Printf("  wrote %s, %s\n", jsonPath, sarifPath)
	fmt.Println("\nReview the diff, then either accept it (`nox mcp baseline --force`) or treat it as an incident.")
}

func severityLine(sev map[findings.Severity]int) string {
	if out := findings.FormatSeverityCounts(sev); out != "" {
		return out
	}
	return "none"
}

// printSandboxWarning reminds the operator, on stderr, that the server runs as a
// subprocess and must be sandboxed if untrusted. Always printed before launch so
// the risk is never silent.
func printSandboxWarning(serverCmd []string) {
	fmt.Fprintf(os.Stderr, "[sandbox] launching MCP server as a subprocess: %v\n", serverCmd)
	fmt.Fprintln(os.Stderr, "[sandbox] if this server is untrusted, STOP and run it in an isolated sandbox (no network, read-only FS). See `nox mcp --help`.")
}
