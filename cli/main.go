// Package main is the entry point for the nox CLI.
package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/replay"
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
	// Route slog to stderr at warn level. Nothing configured a handler before,
	// so every slog.Warn the pipeline emits about degraded checks — including
	// the OSV degradation warning added specifically to prevent silent failure
	// — was reaching nobody. NOX_LOG_LEVEL surfaces the rest.
	level := slog.LevelWarn
	if lvl := os.Getenv("NOX_LOG_LEVEL"); lvl != "" {
		var parsed slog.Level
		if err := parsed.UnmarshalText([]byte(lvl)); err == nil {
			level = parsed
		}
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

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
	case "format", "output", "rules":
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
	bootstrapState()

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

	// Defaults are deliberately EMPTY so "flag absent" is distinguishable from
	// "flag explicitly set to the default". The built-in defaults are applied by
	// resolveOutputFormat/resolveOutputDir after config is read. See the comment
	// on those functions.
	fs.StringVar(&formatFlag, "format", "", usageFormat)
	fs.StringVar(&outputDir, "output", "", usageOutput)
	fs.StringVar(&rulesFlag, "rules", "", usageRules)
	fs.BoolVar(&quietFlag, "quiet", false, usageQuiet)
	fs.BoolVar(&quietFlag, "q", false, usageQuietSh)
	fs.BoolVar(&verboseFlag, "verbose", false, usageVerbose)
	fs.BoolVar(&verboseFlag, "v", false, usageVerbSh)
	fs.BoolVar(&versionFlag, "version", false, usageVersion)

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: nox <command> [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  scan <path>      Scan a directory for security issues\n")
		fmt.Fprintf(os.Stderr, "  show [path]      Inspect findings interactively\n")
		fmt.Fprintf(os.Stderr, "  explain <path>   Explain findings using an LLM\n")
		fmt.Fprintf(os.Stderr, "  confirm          ACTIVE: dynamically confirm AI prompt-injection findings against a running --target (opt-in)\n")
		fmt.Fprintf(os.Stderr, "  attack <cmd>     Dynamic exploit validation: plan (offline), run, replay, regress (ACTIVE, --authorize)\n")
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
		fmt.Fprintf(os.Stderr, "  fix              Apply OSV dep upgrades (--actions also bumps GitHub Actions pins)\n")
		fmt.Fprintf(os.Stderr, "  doctor           Report environment, plugin state, config sanity\n")
		fmt.Fprintf(os.Stderr, "  agent-graph      Render agent capability lattice (mermaid/dot)\n")
		fmt.Fprintf(os.Stderr, "  analysis-capabilities  Report what this installation can establish, and what it cannot\n")
		fmt.Fprintf(os.Stderr, "  bench            Scan a corpus directory; report rule fire-rates (--precision <dir> scores P/R/F1 against a labeled corpus)\n")
		fmt.Fprintf(os.Stderr, "  calibrate        Suggest severity overrides from a bench report\n")
		fmt.Fprintf(os.Stderr, "  install          Install plugins listed in .nox.yaml plugins.required\n")
		fmt.Fprintf(os.Stderr, "  uri <uri>        Handle nox:// URI (install action). Use `uri register` to wire OS URL handler\n")
		fmt.Fprintf(os.Stderr, "  completion <sh>  Generate shell completions\n")
		fmt.Fprintf(os.Stderr, "  serve            Start MCP server on stdio\n")
		fmt.Fprintf(os.Stderr, "  mcp <cmd>        Baseline an MCP server's tool manifest and detect drift (rug-pull)\n")
		fmt.Fprintf(os.Stderr, "  lsp              Start LSP server on stdio (publishes findings as editor diagnostics)\n")
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
	case "replay":
		return runReplay(remaining[1:])
	case "why":
		return runWhy(remaining[1:])
	case "confirm":
		return runConfirm(remaining[1:])
	case "attack":
		return runAttack(remaining[1:])
	case "badge":
		return runBadge(remaining[1:])
	case "serve":
		return runServe(remaining[1:])
	case "mcp":
		return runMCP(remaining[1:])
	case "lsp":
		return runLSP(remaining[1:])
	case "registry":
		return runRegistry(remaining[1:])
	case "plugin":
		return runPlugin(remaining[1:])
	case "intel":
		return runIntel(remaining[1:])
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
	case "verify-secrets":
		return runVerifySecrets(remaining[1:])
	case "variants":
		return runVariants(remaining[1:])
	case "doctor":
		return runDoctor(remaining[1:])
	case "agent-graph":
		return runAgentGraph(remaining[1:])
	case "analysis-capabilities":
		return runAnalysisCapabilities(remaining[1:])
	case "bench":
		return runBench(remaining[1:])
	case "calibrate":
		return runCalibrate(remaining[1:])
	case "install":
		return runInstall(remaining[1:])
	case "uri":
		return runURI(remaining[1:])
	case "version":
		fmt.Printf("nox %s (commit: %s, built: %s)\n", version, commit, date)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", command)
		fmt.Fprintln(os.Stderr, "Usage: nox <command> [flags]")
		return 2
	}
}

// parseInterspersed parses fs from args where flags may appear before AND
// after positional arguments. The stdlib flag package stops at the first
// non-flag token, so a flag placed after the path (e.g. "scan . -offline")
// would otherwise be silently dropped (#103). After each positional we
// re-parse the remainder, so every flag is honored regardless of position.
// Returns the positional arguments in order.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positionals []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return positionals, err
		}
		if fs.NArg() == 0 {
			return positionals, nil
		}
		positionals = append(positionals, fs.Arg(0))
		rest = fs.Args()[1:]
		if len(rest) == 0 {
			return positionals, nil
		}
	}
}

// resolveOutputFormat picks the output format from the CLI flag, then
// .nox.yaml, then the built-in default.
//
// The previous form compared the flag's VALUE to its default —
// `if formatFlag == "json" && cfg.Output.Format != ""` — so an explicit
// `-format json` was indistinguishable from the flag being absent, and config
// overrode a value the caller had deliberately typed. The comment above it
// said CLI flags take precedence, which is what everyone assumed.
//
// It disabled the security gate on two repositories: CI ran
// `nox scan … -format json,sarif` and gated on findings.json, both repos had
// `output.format: sarif` in .nox.yaml, so findings.json was never written and
// the gating step skipped on the missing file — and a skipped step is a green
// check. Exit 0, no warning, 20 and 63 ungated SARIF results.
//
// The flags now default to empty, so "absent" is representable and config can
// fill it in without ever overriding an argument that was actually passed.
func resolveOutputFormat(flagValue, configValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if configValue != "" {
		return configValue
	}
	return "json"
}

// resolveOutputDir applies the same precedence to the output directory, which
// carried the identical defect against ".".
func resolveOutputDir(flagValue, configValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if configValue != "" {
		return configValue
	}
	return "."
}

// stagedScanOptions adapts the scan options for a --staged run.
//
// `nox scan --staged` reconstructs the git index into a temporary directory and
// scans that, copying .nox.yaml across so project config still applies. The CLI
// used to call nox.RunStagedScan(target), which passes ScanOptions{} — so every
// flag the operator typed (--rules, --vex, --baseline, --offline, --no-osv,
// --tf-plan, --tracked-only, --no-respect-gitignore) was silently dropped while
// the config file was still honoured. That is #362's inversion again: config
// beat an explicit flag, with no error and no warning. It sat on the pre-commit
// hook path, which is `nox scan --staged`.
//
// Path-valued options are resolved here rather than in the scan pipeline: the
// pipeline joins relative paths against the scan root, which under --staged is
// the temp directory, so a relative --rules/--vex/--baseline would resolve to a
// file that does not exist there. Anchoring them to the real target preserves
// the same "relative to the scan target" meaning a non-staged run has.
func stagedScanOptions(target string, opts nox.ScanOptions) nox.ScanOptions {
	root := nox.ConfigRoot(target)
	opts.CustomRulesPath = absAgainst(root, opts.CustomRulesPath)
	opts.VEXPath = absAgainst(root, opts.VEXPath)
	opts.BaselinePath = absAgainst(root, opts.BaselinePath)
	opts.TerraformPlanPath = absAgainst(root, opts.TerraformPlanPath)
	return opts
}

// absAgainst anchors a relative path to root. Empty and absolute paths are
// returned unchanged so "flag absent" stays representable as "".
func absAgainst(root, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(root, p)
}

// Descriptions for the flags nox accepts before a subcommand.
//
// Constants rather than literals at the registration sites, because
// `nox scan --help` renders the same set (see scanFS.Usage) and two copies of
// a flag's description drift. The registrations themselves stay inline in
// run(), where the alias-drift guard in toplevel_flag_efficacy_test.go can see
// them: -q and --quiet must keep binding one variable, and that guard reads
// the source.
const (
	usageFormat  = "output formats: json,sarif,cdx,spdx,all (comma-separated) (default \"json\")"
	usageOutput  = "output directory for report files (default \".\")"
	usageRules   = "path to custom rules YAML file or directory"
	usageQuiet   = "suppress all output except errors"
	usageQuietSh = "suppress all output except errors (shorthand)"
	usageVerbose = "enable verbose output"
	usageVerbSh  = "enable verbose output (shorthand)"
	usageVersion = "print version and exit"
)

// printGlobalFlags renders the pre-subcommand flags for a subcommand's usage.
//
// They are real and they work — `nox scan . --format cdx` writes an SBOM — but
// they live on the root flag set, so `nox scan --help` listed only the scan set
// and never mentioned them. --format is how nox emits an SBOM at all, which
// made the SBOM look like a capability nox does not have (#489).
//
// Rendered from a throwaway set so this stays a display concern: nothing here
// parses anything, and the descriptions come from the same constants the real
// registrations use.
func printGlobalFlags(out io.Writer) {
	var s1, s2, s3 string
	var b1, b2, b3 bool
	tmp := flag.NewFlagSet("global", flag.ContinueOnError)
	tmp.SetOutput(out)
	tmp.StringVar(&s1, "format", "", usageFormat)
	tmp.StringVar(&s2, "output", "", usageOutput)
	tmp.StringVar(&s3, "rules", "", usageRules)
	tmp.BoolVar(&b1, "quiet", false, usageQuiet)
	tmp.BoolVar(&b1, "q", false, usageQuietSh)
	tmp.BoolVar(&b2, "verbose", false, usageVerbose)
	tmp.BoolVar(&b2, "v", false, usageVerbSh)
	tmp.BoolVar(&b3, "version", false, usageVersion)
	_, _ = fmt.Fprintln(out, "\nGlobal flags (accepted before or after the subcommand):")
	tmp.PrintDefaults()
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
		vexFlag    string
		tfPlanFlag string
	)
	scanFS.BoolVar(&stagedFlag, "staged", false, "scan only git-staged files (index content)")
	scanFS.StringVar(&thresholdFlag, "severity-threshold", "", "minimum severity to report (critical, high, medium, low)")
	var minConfidenceFlag string
	scanFS.StringVar(&minConfidenceFlag, "min-confidence", "", "minimum confidence to report (high, medium, low); drops lower-confidence heuristic findings")
	scanFS.BoolVar(&noOSVFlag, "no-osv", false, "disable OSV.dev vulnerability lookups (offline mode)")
	scanFS.StringVar(&vexFlag, "vex", "", "path to OpenVEX document for vulnerability status overrides")
	scanFS.StringVar(&tfPlanFlag, "tf-plan", "", "path to terraform plan JSON file to scan")
	var (
		historyFlag           bool
		historyDepthFlag      int
		noCacheFlag           bool
		changedSinceFlag      string
		noRespectGitignoreFlg bool
		trackedOnlyFlag       bool
		noAutoInstallFlg      bool
		failOnUnwaivedFlg     bool
		offlineFlag           bool
		failOnDegraded        bool
		sortFlag              string
		evidenceOutFlag       string
	)
	scanFS.BoolVar(&historyFlag, "history", false, "scan git history for secrets in past commits")
	scanFS.IntVar(&historyDepthFlag, "history-depth", 0, "max number of commits to scan (0 = unlimited)")
	// Accepted for compatibility with existing scripts, but the scan pipeline
	// consults no incremental cache — every run is already a full re-scan. The
	// flag previously set ScanOptions.NoCache, which nothing read.
	scanFS.BoolVar(&noCacheFlag, "no-cache", false, "no-op: scans are never cached (accepted for compatibility)")
	scanFS.StringVar(&changedSinceFlag, "changed-since", "", "scan only files changed since the given git ref")
	var baselineFlag string
	scanFS.StringVar(&baselineFlag, "baseline", "", "path to the baseline file whose fingerprints mark known findings as suppressed (default: auto-discover .nox/baseline.json, or .nox.yaml policy.baseline_path)")
	scanFS.BoolVar(&noRespectGitignoreFlg, "no-respect-gitignore", false, "scan paths matched by .gitignore (default: skip them)")
	scanFS.BoolVar(&trackedOnlyFlag, "tracked-only", false, "scan only git-tracked files (git ls-files); exclude untracked working-tree files and submodule contents")
	scanFS.BoolVar(&noAutoInstallFlg, "no-auto-install", false, "skip auto-installing plugins listed in .nox.yaml plugins.required")
	scanFS.BoolVar(&failOnUnwaivedFlg, "fail-on-unwaived", false, "with --vex: only exit non-zero on findings NOT covered by an OpenVEX waiver")
	// For CI that must treat "could not check" as failure rather than success —
	// e.g. a runner where OSV is firewalled, or a required plugin is missing.
	// Without this, an incomplete scan exits 0 exactly like a clean one.
	scanFS.BoolVar(&failOnDegraded, "fail-on-degraded", false, "exit non-zero if any check could not complete (OSV lookup, plugin, lockfile parse)")
	scanFS.BoolVar(&offlineFlag, "offline", false, "guarantee zero network: disable every feature that could make an outbound connection (no API, no token, no telemetry)")
	scanFS.StringVar(&sortFlag, "sort", "deterministic", "findings.json order: 'deterministic' (rule/path/line) or 'priority' (severity, then reachability, then confidence — most actionable first)")
	// Off by default. The evidence a scan gathers lives out-of-band and is
	// discarded when the scan ends, for the memory reason measured in
	// docs/benchmarks/2026-Q3/ledger-budget.md. This is how you keep it: an
	// operator who wants to ask, later, why nox said what it said asks for the
	// artifact now. A scan that does not ask is byte-identical to before.
	scanFS.StringVar(&evidenceOutFlag, "evidence-out", "", "write the replayable evidence behind this scan to a JSON file (see `nox replay`)")
	var fingerprintVersionFlag string
	scanFS.StringVar(&fingerprintVersionFlag, "fingerprint-version", "", "fingerprint algorithm version (1 = legacy, line+path+content; 2 = line-independent + path-normalised). Default v2 (line-independent) unless NOX_FINGERPRINT_VERSION is set.")
	scanFS.Usage = func() {
		out := scanFS.Output()
		_, _ = fmt.Fprintln(out, "Usage of scan:")
		scanFS.PrintDefaults()
		printGlobalFlags(out)
	}
	positionals, err := parseInterspersed(scanFS, args)
	if err != nil {
		// flag.ErrHelp means the user asked for -h/--help; the flag package
		// already printed usage, so exit quietly. For a genuine unknown/removed
		// flag, add an actionable hint — a bare "flag provided but not defined"
		// swallowed by a `nox scan … || true` pipeline is how scanning silently
		// stops after an upgrade. Point at -h and the baseline default so the
		// once-removed `-baseline` flag never becomes a silent-disable trap again.
		if err != flag.ErrHelp {
			fmt.Fprintln(os.Stderr, "nox scan: unrecognized flag. Run 'nox scan -h' for the supported flags.")
			fmt.Fprintln(os.Stderr, "Note: the baseline is auto-discovered at .nox/baseline.json — override it with '--baseline <path>' if needed.")
		}
		return 2
	}
	// Wire fingerprint version: explicit flag wins, then env var (handled
	// at package init), then default. Unknown values fall back to default
	// inside findings.SetFingerprintVersion.
	switch fingerprintVersionFlag {
	case "":
		// no-op; init() already consulted NOX_FINGERPRINT_VERSION
	case "1", "v1":
		findings.SetFingerprintVersion(findings.FingerprintV1)
	case "2", "v2":
		findings.SetFingerprintVersion(findings.FingerprintV2)
	default:
		fmt.Fprintf(os.Stderr, "error: --fingerprint-version must be 1 or 2, got %q\n", fingerprintVersionFlag)
		return 2
	}

	if len(positionals) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: nox scan <path> [flags]")
		return 2
	}
	target := positionals[0]

	// Load project config for output defaults.
	cfg, err := nox.LoadScanConfig(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading .nox.yaml: %v\n", err)
		return 2
	}

	// Auto-install required plugins from .nox.yaml plugins.required when
	// the project opts in (default) and the operator hasn't passed
	// --no-auto-install. Failures are non-fatal — the scan still runs.
	if !noAutoInstallFlg && cfg.Plugins.AutoInstallEnabled() && len(cfg.Plugins.Required) > 0 {
		if rc := autoInstallProjectPlugins(target, &cfg.Plugins, quiet); rc != 0 && verbose {
			fmt.Fprintf(os.Stderr, "[warn] auto-install returned %d; some plugins may be missing\n", rc)
		}
	}

	// Precedence is flag > config > default.
	formatFlag = resolveOutputFormat(formatFlag, cfg.Output.Format)
	outputDir = resolveOutputDir(outputDir, cfg.Output.Directory)

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

	opts := nox.ScanOptions{
		CustomRulesPath:    rulesPath,
		DisableOSV:         noOSVFlag,
		Offline:            offlineFlag,
		VEXPath:            vexFlag,
		TerraformPlanPath:  tfPlanFlag,
		ChangedSince:       changedSinceFlag,
		NoRespectGitignore: noRespectGitignoreFlg,
		TrackedOnly:        trackedOnlyFlag,
		BaselinePath:       baselineFlag,
	}

	var result *nox.ScanResult
	switch {
	case stagedFlag:
		result, err = nox.RunStagedScanWithOptions(target, stagedScanOptions(target, opts))
	case historyFlag:
		historyOpts := nox.HistoryScanOptions{
			MaxDepth:    historyDepthFlag,
			ScanOptions: nox.ScanOptions{CustomRulesPath: rulesPath},
		}
		result, err = nox.RunHistoryScan(target, &historyOpts)
	default:
		// The only place a scan is permitted to contribute. Every other caller
		// of RunScanWithOptions — diff, preview, bench — derives nothing and
		// sends nothing.
		opts.ContributeObservations = true
		opts.ToolVersion = version
		// The artifact IS the reasoning. Asking for one without turning
		// recording on would write a file full of verdicts with no evidence
		// behind them, which replays as "nothing was checked" — a confusing
		// way to discover a flag did not do what it said.
		if evidenceOutFlag != "" {
			opts.RecordReasoning = true
		}
		result, err = nox.RunScanWithOptions(target, opts)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: scan failed: %v\n", err)
		return 2
	}

	if evidenceOutFlag != "" {
		art := result.EvidenceArtifact(replay.Inputs{
			GeneratedAt: report.GeneratedAt(),
			ToolName:    "nox",
			ToolVersion: version,
			Target:      target,
			Offline:     offlineFlag,
		})
		if werr := art.WriteFile(evidenceOutFlag); werr != nil {
			// Not fatal. The scan's own results are complete and already
			// computed; failing the run because an extra artifact could not be
			// written would turn an optional record into a way to break CI.
			fmt.Fprintf(os.Stderr, "warning: could not write evidence artifact: %v\n", werr)
		} else if !quiet {
			fmt.Fprintf(os.Stderr, "evidence: wrote %s (%d subject(s), %d verdict(s)) — replay with `nox replay %s`\n",
				evidenceOutFlag, len(art.Subjects), len(art.Findings), evidenceOutFlag)
		}
	}

	activeFindings := result.Findings.ActiveFindings()

	// --fail-on-unwaived: when --vex is set, treat findings whose VEX
	// status is `under_investigation` as covered for exit-code purposes.
	// Operators waiving by RuleID without classifying each entry get
	// the same green CI as `not_affected`.
	if failOnUnwaivedFlg && vexFlag != "" {
		var unwaived []findings.Finding
		for i := range activeFindings {
			if activeFindings[i].Status == findings.StatusVEXUnderInvestigation {
				continue
			}
			unwaived = append(unwaived, activeFindings[i])
		}
		activeFindings = unwaived
	}

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

	// Apply confidence threshold filtering if specified. Lets operators drop
	// lower-confidence heuristic findings (e.g. typosquatting suspicions) while
	// keeping high-confidence ones.
	if minConfidenceFlag != "" {
		threshold := findings.Confidence(minConfidenceFlag)
		var filtered []findings.Finding
		for i := range activeFindings {
			if nox.ConfidenceMeetsThreshold(activeFindings[i].Confidence, threshold) {
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
		if offlineFlag {
			fmt.Println("[offline] zero-network guarantee: no OSV, no API, no token, no telemetry (recorded in findings.json meta)")
		}
	}

	// Report incomplete checks even under --quiet, and on stderr. A scan that
	// could not run part of itself must never look like a clean scan: quiet
	// mode suppresses noise, not a warning that the results are partial.
	//
	// The --fail-on-degraded exit is deliberately NOT taken here: returning
	// before report generation threw away findings.json, the SARIF and the
	// SBOM, so a pipeline that tripped the flag lost the findings it did
	// collect and had nothing to upload. The exit is applied after reports are
	// written; see below.
	for _, d := range result.Degradations {
		fmt.Fprintf(os.Stderr, "[degraded] %s\n  impact: %s\n", d.Detail, d.Impact)
	}

	// Config nox does not act on used to be printed here, by this adapter only.
	// It is now recorded in core as a degrade.Config degradation and rendered by
	// the loop above, so the MCP server, the LSP and findings.json all report it
	// too — an agent scanning over MCP had no other way to learn that the policy
	// it configured was not in force.

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
			r.Offline = offlineFlag
			r.Prioritize = sortFlag == "priority"
			r.SASTLanguages = result.SASTProfile
			r.Degradations = report.DegradationsFrom(result.Degradations)
			r.Enrichments = result.Enrichments
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

	// An incomplete scan outranks the findings verdict: a policy gate that
	// passed on partial results has not actually been satisfied. Applied here,
	// after reports are written, so CI still gets its artifacts.
	if len(result.Degradations) > 0 && failOnDegraded {
		fmt.Fprintf(os.Stderr, "error: %d check(s) did not complete and --fail-on-degraded is set\n",
			len(result.Degradations))
		return 2
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
