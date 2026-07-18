package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/nox-hq/nox/core/findings"
)

// curatedAutoCorpus is the default benchmark corpus when --autocorpus
// is set. Each entry targets the AI app developer ICP: LLM client
// SDKs (openai, anthropic), agent frameworks (langchain, llamaindex,
// crewai, agent-go, vercel-ai), and the MCP reference SDK. Pinned to
// specific refs so bench output is reproducible across runs.
var curatedAutoCorpus = []struct {
	Repo string
	Ref  string
}{
	{Repo: "langchain-ai/langchain", Ref: "v0.3.7"},
	{Repo: "run-llama/llama_index", Ref: "v0.12.0"},
	{Repo: "openai/openai-python", Ref: "v1.54.0"},
	{Repo: "anthropics/anthropic-sdk-python", Ref: "v0.40.0"},
	{Repo: "felixgeelhaar/agent-go", Ref: "main"},
	{Repo: "modelcontextprotocol/python-sdk", Ref: "main"},
	{Repo: "vercel/ai", Ref: "main"},
	{Repo: "joaomdmoura/crewai", Ref: "main"},
}

// runBench scans every directory in --corpus and produces a fire-rate
// report. With --autocorpus, nox first clones the curated benchmark
// set into a temp directory and runs the same harness against it —
// reproducible numbers without manual setup.
func runBench(args []string) int {
	// `nox bench --precision <corpus>` is a distinct mode: instead of
	// fire-rates over many projects, it scores one labeled corpus for
	// precision/recall/F1 against inline `nox-expect` ground truth. It is
	// routed early so it can own its own flag set without colliding with the
	// fire-rate flags (e.g. --min-precision, --json).
	if hasFlag(args, "precision") {
		return runBenchPrecision(args)
	}

	fs := flag.NewFlagSet("bench", flag.ContinueOnError)
	var (
		corpusDir  string
		output     string
		quiet      bool
		fmtFlag    string
		autoCorpus bool
	)
	fs.StringVar(&corpusDir, "corpus", "corpus", "directory containing one subdirectory per project to scan")
	fs.StringVar(&output, "output", "", "destination path (defaults to stdout)")
	fs.BoolVar(&quiet, "quiet", false, "suppress per-project progress logs")
	fs.StringVar(&fmtFlag, "format", "json", "report format: json or markdown")
	fs.BoolVar(&autoCorpus, "autocorpus", false, "clone the curated benchmark corpus into a temp directory and scan that instead of --corpus")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if autoCorpus {
		dir, err := materialiseAutoCorpus(quiet)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: materialising autocorpus: %v\n", err)
			return 2
		}
		corpusDir = dir
	}

	entries, err := os.ReadDir(corpusDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading corpus dir %s: %v\n", corpusDir, err)
		return 2
	}

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: locating nox binary: %v\n", err)
		return 2
	}

	report := BenchReport{
		StartedAt: time.Now().UTC().Format(time.RFC3339),
		NoxBinary: exe,
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		project := filepath.Join(corpusDir, e.Name())
		if !quiet {
			fmt.Fprintf(os.Stderr, "[bench] scanning %s\n", project)
		}
		summary, err := scanProject(exe, project)
		if err != nil {
			report.Failed = append(report.Failed, FailedProject{Path: project, Error: err.Error()})
			continue
		}
		report.Projects = append(report.Projects, summary)
	}

	report.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	aggregateRuleFireRates(&report)

	var out []byte
	switch fmtFlag {
	case "json":
		out, err = json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: marshalling report: %v\n", err)
			return 2
		}
	case "markdown":
		out = []byte(renderBenchMarkdown(&report))
	default:
		fmt.Fprintf(os.Stderr, "error: unknown format %q\n", fmtFlag)
		return 2
	}

	if output == "" {
		fmt.Println(string(out))
		return 0
	}
	if err := os.WriteFile(output, out, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", output, err)
		return 2
	}
	if !quiet {
		fmt.Fprintf(os.Stderr, "[bench] wrote %s (%d projects)\n", output, len(report.Projects))
	}
	return 0
}

// BenchReport is the top-level bench output. Stable JSON shape so
// downstream tooling can join across runs.
type BenchReport struct {
	StartedAt    string           `json:"started_at"`
	FinishedAt   string           `json:"finished_at"`
	NoxBinary    string           `json:"nox_binary"`
	Projects     []ProjectSummary `json:"projects"`
	Failed       []FailedProject  `json:"failed,omitempty"`
	RuleFireRate map[string]int   `json:"rule_fire_rate,omitempty"`
}

type ProjectSummary struct {
	Path     string         `json:"path"`
	Findings int            `json:"findings"`
	Duration string         `json:"duration"`
	ByRule   map[string]int `json:"by_rule"`
	BySev    map[string]int `json:"by_severity"`
}

type FailedProject struct {
	Path  string `json:"path"`
	Error string `json:"error"`
}

func scanProject(noxPath, project string) (ProjectSummary, error) {
	tmpOut, err := os.MkdirTemp("", "nox-bench-*")
	if err != nil {
		return ProjectSummary{}, err
	}
	defer os.RemoveAll(tmpOut) //nolint:errcheck // best-effort cleanup

	start := time.Now()
	cmd := exec.Command(noxPath, "scan", project, "--output", tmpOut, "--quiet")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		// nox returns 1 on findings — treat that as success here. We
		// only care about scan errors.
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
			return ProjectSummary{}, err
		}
	}
	duration := time.Since(start).Round(time.Millisecond)

	raw, err := os.ReadFile(filepath.Join(tmpOut, "findings.json"))
	if err != nil {
		return ProjectSummary{}, err
	}
	var doc struct {
		Findings []findings.Finding `json:"findings"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return ProjectSummary{}, err
	}

	byRule := map[string]int{}
	bySev := map[string]int{}
	for i := range doc.Findings {
		byRule[doc.Findings[i].RuleID]++
		bySev[string(doc.Findings[i].Severity)]++
	}

	return ProjectSummary{
		Path:     project,
		Findings: len(doc.Findings),
		Duration: duration.String(),
		ByRule:   byRule,
		BySev:    bySev,
	}, nil
}

// aggregateRuleFireRates fills RuleFireRate with the count of unique
// projects in which each rule fired at least once. Operators use this
// to decide which rules carry their weight (high count = signal) vs
// which fire universally and should be downgraded (every project = noise).
func aggregateRuleFireRates(report *BenchReport) {
	counts := map[string]int{}
	for i := range report.Projects {
		for rule := range report.Projects[i].ByRule {
			counts[rule]++
		}
	}
	report.RuleFireRate = counts
}

func renderBenchMarkdown(report *BenchReport) string {
	var b strings.Builder
	b.WriteString("# Nox bench report\n\n")
	fmt.Fprintf(&b, "- Started: %s\n", report.StartedAt)
	fmt.Fprintf(&b, "- Finished: %s\n", report.FinishedAt)
	fmt.Fprintf(&b, "- Projects scanned: %d (failed: %d)\n\n", len(report.Projects), len(report.Failed))

	b.WriteString("## Per-project summary\n\n")
	b.WriteString("| Project | Findings | Duration |\n|---|---|---|\n")
	for i := range report.Projects {
		p := &report.Projects[i]
		fmt.Fprintf(&b, "| %s | %d | %s |\n", p.Path, p.Findings, p.Duration)
	}
	b.WriteString("\n")

	b.WriteString("## Rule fire-rate (number of projects each rule fired in)\n\n")
	type kv struct {
		rule  string
		count int
	}
	var pairs []kv
	for r, c := range report.RuleFireRate {
		pairs = append(pairs, kv{r, c})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count != pairs[j].count {
			return pairs[i].count > pairs[j].count
		}
		return pairs[i].rule < pairs[j].rule
	})
	b.WriteString("| Rule | Projects |\n|---|---|\n")
	for _, p := range pairs {
		fmt.Fprintf(&b, "| %s | %d |\n", p.rule, p.count)
	}
	if len(report.Failed) > 0 {
		b.WriteString("\n## Failed projects\n\n")
		for _, f := range report.Failed {
			fmt.Fprintf(&b, "- `%s` — %s\n", f.Path, f.Error)
		}
	}
	return b.String()
}

// materialiseAutoCorpus clones every entry in curatedAutoCorpus into
// a fresh temp directory and returns its path. Repos already present
// from a previous run are skipped (the temp dir is unique per
// invocation, so this only matters when callers pass the same
// directory twice — operators don't, but bench tests do).
func materialiseAutoCorpus(quiet bool) (string, error) {
	dir, err := os.MkdirTemp("", "nox-bench-autocorpus-*")
	if err != nil {
		return "", err
	}
	for _, entry := range curatedAutoCorpus {
		owner, repo := splitRepoSlug(entry.Repo)
		if owner == "" {
			continue
		}
		dest := filepath.Join(dir, owner+"--"+repo)
		if !quiet {
			fmt.Fprintf(os.Stderr, "[bench] cloning %s@%s\n", entry.Repo, entry.Ref)
		}
		cmd := exec.Command("git", "clone", "--depth", "1",
			"--branch", entry.Ref,
			"https://github.com/"+entry.Repo+".git",
			dest)
		out, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[bench] skipping %s: %v\n%s\n", entry.Repo, err, out)
			continue
		}
	}
	return dir, nil
}

func splitRepoSlug(slug string) (owner, repo string) {
	for i := 0; i < len(slug); i++ {
		if slug[i] == '/' {
			return slug[:i], slug[i+1:]
		}
	}
	return "", slug
}
