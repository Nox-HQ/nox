package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/catalog"
	"github.com/nox-hq/nox/core/detail"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/cli/tui"

	"golang.org/x/term"
)

// runShow implements the "nox show" command.
func runShow(args []string) int {
	// Extract positional args (paths) before parsing flags so that
	// "nox show . --severity critical" works like "nox show --severity critical .".
	var flagArgs []string
	var positionalArgs []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			flagArgs = append(flagArgs, args[i])
			// If this flag takes a value (not a boolean), consume the next arg too.
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") &&
				!isBoolFlag(args[i]) {
				i++
				flagArgs = append(flagArgs, args[i])
			}
		} else {
			positionalArgs = append(positionalArgs, args[i])
		}
	}

	fs := flag.NewFlagSet("show", flag.ContinueOnError)

	var (
		severity    string
		rulePattern string
		filePattern string
		input       string
		jsonOutput  bool
		contextN    int
	)

	fs.StringVar(&severity, "severity", "", "filter by severity: critical,high,medium,low,info (comma-separated)")
	fs.StringVar(&rulePattern, "rule", "", "filter by rule pattern (e.g., AI-*, SEC-001)")
	fs.StringVar(&filePattern, "file", "", "filter by file pattern (e.g., src/)")
	fs.StringVar(&input, "input", "", "path to findings.json (default: run scan)")
	fs.BoolVar(&jsonOutput, "json", false, "output JSON instead of TUI")
	fs.IntVar(&contextN, "context", 5, "number of source context lines")

	if err := fs.Parse(flagArgs); err != nil {
		return 2
	}
	// Merge any remaining positional args from flag parse with pre-extracted ones.
	positionalArgs = append(positionalArgs, fs.Args()...)

	// Load or generate findings.
	var store *detail.Store
	var basePath string

	if input != "" {
		var err error
		store, err = detail.LoadFromFile(input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 2
		}
		basePath = store.BasePath()
	} else {
		// Determine target path.
		target := "."
		if len(positionalArgs) > 0 {
			target = positionalArgs[0]
		}

		fmt.Printf("nox — scanning %s\n", target)
		result, err := nox.RunScan(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: scan failed: %v\n", err)
			return 2
		}

		findingCount := len(result.Findings.Findings())
		fmt.Printf("[results] %d findings\n", findingCount)

		if findingCount == 0 {
			fmt.Println("[show] no findings to display")
			return 0
		}

		store = detail.LoadFromSet(result.Findings, target)
		basePath = target
	}

	// Build filter.
	filter := detail.Filter{
		RulePattern: rulePattern,
		FilePattern: filePattern,
	}
	if severity != "" {
		for _, s := range strings.Split(severity, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				filter.Severities = append(filter.Severities, findings.Severity(s))
			}
		}
	}

	filtered := store.Filter(filter)

	// Build catalog.
	cat := catalog.Catalog()

	// Non-interactive: JSON output.
	if jsonOutput || !isTerminal() {
		return showJSON(filtered, basePath, store.All(), cat, contextN)
	}

	// Interactive: TUI.
	filteredStore := detail.LoadFromSet(toFindingSet(filtered), basePath)
	m := tui.New(filteredStore, cat, contextN)
	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: TUI failed: %v\n", err)
		return 2
	}
	return 0
}

func showJSON(ff []findings.Finding, basePath string, allFindings []findings.Finding, cat map[string]catalog.RuleMeta, contextLines int) int {
	var details []*detail.FindingDetail
	for _, f := range ff {
		details = append(details, detail.Enrich(f, basePath, allFindings, cat, contextLines))
	}

	data, err := json.MarshalIndent(details, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: marshalling JSON: %v\n", err)
		return 2
	}

	fmt.Println(string(data))
	return 0
}

func toFindingSet(ff []findings.Finding) *findings.FindingSet {
	fs := findings.NewFindingSet()
	for _, f := range ff {
		fs.Add(f)
	}
	return fs
}

// isBoolFlag returns true if the given flag name is a boolean flag
// (i.e., it does not consume a following value argument).
func isBoolFlag(name string) bool {
	name = strings.TrimLeft(name, "-")
	switch name {
	case "json":
		return true
	default:
		return false
	}
}

// isTerminal returns true if stdout is connected to a terminal.
func isTerminal() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}
