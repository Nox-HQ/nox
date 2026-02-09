// Package main is the entry point for the nox CLI.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/report"
	"github.com/nox-hq/nox/core/report/sarif"
	"github.com/nox-hq/nox/core/report/sbom"
	"github.com/nox-hq/nox/server"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// run executes the CLI and returns the exit code.
// 0 = clean (no findings), 1 = findings detected, 2 = error.
func run(args []string) int {
	fs := flag.NewFlagSet("nox", flag.ContinueOnError)

	var (
		formatFlag  string
		outputDir   string
		quietFlag   bool
		verboseFlag bool
		versionFlag bool
	)

	fs.StringVar(&formatFlag, "format", "json", "output formats: json,sarif,cdx,spdx,all (comma-separated)")
	fs.StringVar(&outputDir, "output", ".", "output directory for report files")
	fs.BoolVar(&quietFlag, "quiet", false, "suppress all output except errors")
	fs.BoolVar(&quietFlag, "q", false, "suppress all output except errors (shorthand)")
	fs.BoolVar(&verboseFlag, "verbose", false, "enable verbose output")
	fs.BoolVar(&verboseFlag, "v", false, "enable verbose output (shorthand)")
	fs.BoolVar(&versionFlag, "version", false, "print version and exit")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: nox <command> [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  scan <path>    Scan a directory for security issues\n")
		fmt.Fprintf(os.Stderr, "  explain <path> Explain findings using an LLM\n")
		fmt.Fprintf(os.Stderr, "  serve          Start MCP server on stdio\n")
		fmt.Fprintf(os.Stderr, "  registry       Manage plugin registries\n")
		fmt.Fprintf(os.Stderr, "  plugin         Manage and invoke plugins\n")
		fmt.Fprintf(os.Stderr, "  version        Print version and exit\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if versionFlag {
		fmt.Printf("nox %s (commit: %s, built: %s)\n", version, commit, date)
		return 0
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: nox <command> [flags]")
		return 2
	}

	command := remaining[0]
	switch command {
	case "scan":
		if len(remaining) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: nox scan <path> [flags]")
			return 2
		}
		return runScan(remaining[1], formatFlag, outputDir, quietFlag, verboseFlag)
	case "explain":
		return runExplain(remaining[1:])
	case "serve":
		return runServe(remaining[1:])
	case "registry":
		return runRegistry(remaining[1:])
	case "plugin":
		return runPlugin(remaining[1:])
	case "version":
		fmt.Printf("nox %s (commit: %s, built: %s)\n", version, commit, date)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", command)
		fmt.Fprintln(os.Stderr, "Usage: nox <command> [flags]")
		return 2
	}
}

func runScan(target, formatFlag, outputDir string, quiet, verbose bool) int {
	formats := parseFormats(formatFlag)

	if !quiet {
		fmt.Printf("nox %s — scanning %s\n", version, target)
	}

	if verbose {
		fmt.Println("[discover] walking directory...")
	}

	result, err := nox.RunScan(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: scan failed: %v\n", err)
		return 2
	}

	findingCount := len(result.Findings.Findings())
	pkgCount := len(result.Inventory.Packages())

	if !quiet {
		fmt.Printf("[results] %d findings, %d dependencies, %d AI components\n",
			findingCount, pkgCount, len(result.AIInventory.Components))
	}

	// Generate reports.
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error: creating output directory: %v\n", err)
		return 2
	}

	for _, format := range formats {
		switch format {
		case "json":
			path := filepath.Join(outputDir, "findings.json")
			r := report.NewJSONReporter(version)
			if err := r.WriteToFile(result.Findings, path); err != nil {
				fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", path, err)
				return 2
			}
			if verbose {
				fmt.Printf("[report] wrote %s\n", path)
			}

		case "sarif":
			path := filepath.Join(outputDir, "results.sarif")
			r := sarif.NewReporter(version, nil)
			if err := r.WriteToFile(result.Findings, path); err != nil {
				fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", path, err)
				return 2
			}
			if verbose {
				fmt.Printf("[report] wrote %s\n", path)
			}

		case "cdx":
			path := filepath.Join(outputDir, "sbom.cdx.json")
			r := sbom.NewCycloneDXReporter(version)
			if err := r.WriteToFile(result.Inventory, path); err != nil {
				fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", path, err)
				return 2
			}
			if verbose {
				fmt.Printf("[report] wrote %s\n", path)
			}

		case "spdx":
			path := filepath.Join(outputDir, "sbom.spdx.json")
			r := sbom.NewSPDXReporter(version)
			if err := r.WriteToFile(result.Inventory, path); err != nil {
				fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", path, err)
				return 2
			}
			if verbose {
				fmt.Printf("[report] wrote %s\n", path)
			}
		}
	}

	// Always write AI inventory if components were found.
	if len(result.AIInventory.Components) > 0 {
		path := filepath.Join(outputDir, "ai.inventory.json")
		if err := result.AIInventory.WriteFile(path); err != nil {
			fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", path, err)
			return 2
		}
		if verbose {
			fmt.Printf("[report] wrote %s\n", path)
		}
	}

	if !quiet {
		fmt.Println("[done]")
	}

	if findingCount > 0 {
		return 1
	}
	return 0
}

func runServe(args []string) int {
	serveFS := flag.NewFlagSet("serve", flag.ContinueOnError)
	var allowedPaths string
	serveFS.StringVar(&allowedPaths, "allowed-paths", "", "comma-separated list of allowed workspace paths")

	if err := serveFS.Parse(args); err != nil {
		return 2
	}

	var paths []string
	if allowedPaths != "" {
		for _, p := range strings.Split(allowedPaths, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				paths = append(paths, p)
			}
		}
	}

	srv := server.New(version, paths)
	if err := srv.Serve(); err != nil {
		fmt.Fprintf(os.Stderr, "error: MCP server failed: %v\n", err)
		return 2
	}
	return 0
}

// parseFormats splits the comma-separated format flag into individual format
// strings. "all" expands to all supported formats.
func parseFormats(flag string) []string {
	if flag == "all" {
		return []string{"json", "sarif", "cdx", "spdx"}
	}

	var formats []string
	for _, f := range strings.Split(flag, ",") {
		f = strings.TrimSpace(f)
		if f != "" {
			formats = append(formats, f)
		}
	}
	if len(formats) == 0 {
		return []string{"json"}
	}
	return formats
}
