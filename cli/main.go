// Package main is the entry point for the nox CLI.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/report"
	htmlreport "github.com/nox-hq/nox/core/report/html"
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

// extractInterspersedArgs reorders args so that known top-level flags come
// before positional arguments, allowing "nox scan . --format sarif" to work
// the same as "nox --format sarif scan .". Subcommand-specific flags (e.g.,
// --severity, --json for "show") are left in place for the subcommand to parse.
//
// The string flags --format and --output are only extracted for the "scan"
// subcommand, since other subcommands may define their own --output flag.
// Bool flags (-q, -v, --version) are always extracted regardless of subcommand.
func extractInterspersedArgs(args []string) []string {
	// Determine the subcommand so we know whether to extract --format/--output.
	subcommand := ""
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			subcommand = arg
			break
		}
	}

	var flags, rest []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			rest = append(rest, args[i:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") {
			rest = append(rest, arg)
			continue
		}
		// Extract the flag name (strip leading dashes, handle --flag=value).
		name := strings.TrimLeft(arg, "-")
		if eq := strings.Index(name, "="); eq >= 0 {
			name = name[:eq]
		}
		switch {
		case isTopLevelBoolFlag(name):
			flags = append(flags, arg)
		case subcommand == "scan" && isTopLevelStringFlag(name):
			flags = append(flags, arg)
			// Consume the value unless it was --flag=value.
			if !strings.Contains(arg, "=") && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		default:
			// Unknown flag — belongs to a subcommand, leave in place.
			rest = append(rest, arg)
		}
	}
	return append(flags, rest...)
}

func isTopLevelBoolFlag(name string) bool {
	switch name {
	case "quiet", "q", "verbose", "v", "version", "no-cache":
		return true
	}
	return false
}

func isTopLevelStringFlag(name string) bool {
	switch name {
	case "format", "output", "rules", "changed-since":
		return true
	}
	return false
}

// run executes the CLI and returns the exit code.
// 0 = clean (no findings), 1 = findings detected, 2 = error.
func run(args []string) int {
	// Register any plugin binaries shipped alongside the main binary.
	// Idempotent; runs once per invocation and is silent on failure so
	// it never blocks the user-facing CLI.
	bootstrapBundledPlugins()

	args = extractInterspersedArgs(args)
	fs := flag.NewFlagSet("nox", flag.ContinueOnError)

	var (
		formatFlag  string
		outputDir   string
		rulesFlag   string
		quietFlag   bool
		verboseFlag bool
		versionFlag bool
	)

	fs.StringVar(&formatFlag, "format", "json", "output formats: json,sarif,cdx,spdx,all (comma-separated)")
	fs.StringVar(&outputDir, "output", ".", "output directory for report files")
	fs.StringVar(&rulesFlag, "rules", "", "path to custom rules YAML file or directory")
	fs.BoolVar(&quietFlag, "quiet", false, "suppress all output except errors")
	fs.BoolVar(&quietFlag, "q", false, "suppress all output except errors (shorthand)")
	fs.BoolVar(&verboseFlag, "verbose", false, "enable verbose output")
	fs.BoolVar(&verboseFlag, "v", false, "enable verbose output (shorthand)")
	fs.BoolVar(&versionFlag, "version", false, "print version and exit")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: nox <command> [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  scan <path>      Scan a directory for security issues\n")
		fmt.Fprintf(os.Stderr, "  show [path]      Inspect findings interactively\n")
		fmt.Fprintf(os.Stderr, "  explain <path>   Explain findings using an LLM\n")
		fmt.Fprintf(os.Stderr, "  badge [path]     Generate an SVG status badge\n")
		fmt.Fprintf(os.Stderr, "  baseline <cmd>   Manage finding baselines\n")
		fmt.Fprintf(os.Stderr, "  diff [path]      Show findings in changed files\n")
		fmt.Fprintf(os.Stderr, "  watch [path]     Watch for changes and re-scan\n")
		fmt.Fprintf(os.Stderr, "  protect <cmd>    Manage git pre-commit hook\n")
		fmt.Fprintf(os.Stderr, "  annotate         Annotate a PR with findings\n")
		fmt.Fprintf(os.Stderr, "  dashboard [path] Generate HTML security dashboard\n")
		fmt.Fprintf(os.Stderr, "  cache <cmd>      Manage scan cache\n")
		fmt.Fprintf(os.Stderr, "  vex <cmd>        OpenVEX waiver document tools (vex init)\n")
		fmt.Fprintf(os.Stderr, "  install-hook     Install pre-commit/pre-push git hooks\n")
		fmt.Fprintf(os.Stderr, "  fix              Apply OSV fixed_in remediation upgrades\n")
		fmt.Fprintf(os.Stderr, "  doctor           Report environment, plugin state, config sanity\n")
		fmt.Fprintf(os.Stderr, "  agent-graph      Render agent capability lattice (mermaid/dot)\n")
		fmt.Fprintf(os.Stderr, "  bench            Scan a corpus directory; report rule fire-rates\n")
		fmt.Fprintf(os.Stderr, "  calibrate        Suggest severity overrides from a bench report\n")
		fmt.Fprintf(os.Stderr, "  completion <sh>  Generate shell completions\n") // nox:ignore AI-006 -- CLI help text
		fmt.Fprintf(os.Stderr, "  serve            Start MCP server on stdio\n")
		fmt.Fprintf(os.Stderr, "  registry         Manage plugin registries\n")
		fmt.Fprintf(os.Stderr, "  plugin           Manage and invoke plugins\n")
		fmt.Fprintf(os.Stderr, "  version          Print version and exit\n\n")
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
		return runScan(remaining[1:], formatFlag, outputDir, rulesFlag, quietFlag, verboseFlag)
	case "protect":
		return runProtect(remaining[1:])
	case "show":
		return runShow(remaining[1:])
	case "explain":
		return runExplain(remaining[1:])
	case "badge":
		return runBadge(remaining[1:])
	case "serve":
		return runServe(remaining[1:])
	case "registry":
		return runRegistry(remaining[1:])
	case "plugin":
		return runPlugin(remaining[1:])
	case "cache":
		return runCache(remaining[1:])
	case "baseline":
		return runBaseline(remaining[1:])
	case "diff":
		return runDiff(remaining[1:])
	case "watch":
		return runWatch(remaining[1:])
	case "completion":
		return runCompletion(remaining[1:])
	case "annotate":
		return runAnnotate(remaining[1:])
	case "dashboard":
		return runDashboard(remaining[1:])
	case "vex":
		return runVex(remaining[1:])
	case "install-hook":
		return runInstallHook(remaining[1:])
	case "fix":
		return runFix(remaining[1:])
	case "doctor":
		return runDoctor(remaining[1:])
	case "agent-graph":
		return runAgentGraph(remaining[1:])
	case "bench":
		return runBench(remaining[1:])
	case "calibrate":
		return runCalibrate(remaining[1:])
	case "version":
		fmt.Printf("nox %s (commit: %s, built: %s)\n", version, commit, date)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", command)
		fmt.Fprintln(os.Stderr, "Usage: nox <command> [flags]")
		return 2
	}
}

func runScan(args []string, formatFlag, outputDir, rulesPath string, quiet, verbose bool) int {
	// Parse scan-specific flags.
	scanFS := flag.NewFlagSet("scan", flag.ContinueOnError)
	var (
		stagedFlag    bool
		thresholdFlag string
		noOSVFlag     bool
	)
	var (
		vexFlag        string
		tfPlanFlag     string
	)
	scanFS.BoolVar(&stagedFlag, "staged", false, "scan only git-staged files (index content)")
	scanFS.StringVar(&thresholdFlag, "severity-threshold", "", "minimum severity to report (critical, high, medium, low)")
	scanFS.BoolVar(&noOSVFlag, "no-osv", false, "disable OSV.dev vulnerability lookups (offline mode)")
	scanFS.StringVar(&vexFlag, "vex", "", "path to OpenVEX document for vulnerability status overrides")
	scanFS.StringVar(&tfPlanFlag, "tf-plan", "", "path to terraform plan JSON file to scan")
	var (
		historyFlag           bool
		historyDepthFlag      int
		noCacheFlag           bool
		changedSinceFlag      string
		noRespectGitignoreFlg bool
	)
	scanFS.BoolVar(&historyFlag, "history", false, "scan git history for secrets in past commits")
	scanFS.IntVar(&historyDepthFlag, "history-depth", 0, "max number of commits to scan (0 = unlimited)")
	scanFS.BoolVar(&noCacheFlag, "no-cache", false, "disable incremental scan cache")
	scanFS.StringVar(&changedSinceFlag, "changed-since", "", "scan only files changed since the given git ref")
	scanFS.BoolVar(&noRespectGitignoreFlg, "no-respect-gitignore", false, "scan paths matched by .gitignore (default: skip them)")
	if err := scanFS.Parse(args); err != nil {
		return 2
	}

	if scanFS.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "Usage: nox scan <path> [flags]")
		return 2
	}
	target := scanFS.Arg(0)

	// Load project config for output defaults.
	cfg, err := nox.LoadScanConfig(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading .nox.yaml: %v\n", err)
		return 2
	}

	// Apply output defaults from config (CLI flags take precedence).
	if formatFlag == "json" && cfg.Output.Format != "" {
		formatFlag = cfg.Output.Format
	}
	if outputDir == "." && cfg.Output.Directory != "" {
		outputDir = cfg.Output.Directory
	}

	formats := parseFormats(formatFlag)

	if !quiet {
		switch {
		case stagedFlag:
			fmt.Printf("nox %s — scanning staged files in %s\n", version, target)
		case historyFlag:
			if historyDepthFlag > 0 {
				fmt.Printf("nox %s — scanning git history (%d commits) in %s\n", version, historyDepthFlag, target)
			} else {
				fmt.Printf("nox %s — scanning git history in %s\n", version, target)
			}
		default:
			fmt.Printf("nox %s — scanning %s\n", version, target)
		}
	}

	if verbose {
		fmt.Println("[discover] walking directory...")
	}

	var result *nox.ScanResult
	switch {
	case stagedFlag:
		result, err = nox.RunStagedScan(target)
	case historyFlag:
		historyOpts := nox.HistoryScanOptions{
			MaxDepth:    historyDepthFlag,
			ScanOptions: nox.ScanOptions{CustomRulesPath: rulesPath},
		}
		result, err = nox.RunHistoryScan(target, &historyOpts)
	default:
		opts := nox.ScanOptions{
			CustomRulesPath:    rulesPath,
			DisableOSV:         noOSVFlag,
			VEXPath:            vexFlag,
			TerraformPlanPath:  tfPlanFlag,
			NoCache:            noCacheFlag,
			ChangedSince:       changedSinceFlag,
			NoRespectGitignore: noRespectGitignoreFlg,
		}
		result, err = nox.RunScanWithOptions(target, opts)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: scan failed: %v\n", err)
		return 2
	}

	activeFindings := result.Findings.ActiveFindings()

	// Apply severity threshold filtering if specified.
	if thresholdFlag != "" {
		threshold := findings.Severity(thresholdFlag)
		var filtered []findings.Finding
		for i := range activeFindings {
			if nox.SeverityMeetsThreshold(activeFindings[i].Severity, threshold) {
				filtered = append(filtered, activeFindings[i])
			}
		}
		activeFindings = filtered
	}

	findingCount := len(activeFindings)
	totalCount := len(result.Findings.Findings())
	suppressedCount := totalCount - findingCount
	pkgCount := len(result.Inventory.Packages())

	if !quiet {
		if suppressedCount > 0 {
			fmt.Printf("[results] %d findings (%d suppressed), %d dependencies, %d AI components\n",
				findingCount, suppressedCount, pkgCount, len(result.AIInventory.Components))
		} else {
			fmt.Printf("[results] %d findings, %d dependencies, %d AI components\n",
				findingCount, pkgCount, len(result.AIInventory.Components))
		}
		if summary := familySummary(activeFindings); summary != "" {
			fmt.Printf("[families] %s\n", summary)
		}
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
			r := sarif.NewReporter(version, result.Rules)
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

		case "html":
			path := filepath.Join(outputDir, "report.html")
			r := htmlreport.NewReporter(version)
			if err := r.WriteToFile(result.Findings, path); err != nil {
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

	// Policy evaluation output.
	if result.PolicyResult != nil {
		if !quiet {
			for _, w := range result.PolicyResult.Warnings {
				fmt.Printf("[warn] %s\n", w)
			}
			fmt.Printf("[policy] %s\n", result.PolicyResult.Summary)
		}
	}

	if !quiet {
		printNextStepTips(activeFindings, outputDir)
		fmt.Println("[done]")
	}

	// If policy is configured, use its exit code.
	if result.PolicyResult != nil {
		return result.PolicyResult.ExitCode
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
func parseFormats(fmtFlag string) []string {
	if fmtFlag == "all" {
		return []string{"json", "sarif", "cdx", "spdx", "html"}
	}

	var formats []string
	for _, f := range strings.Split(fmtFlag, ",") {
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
