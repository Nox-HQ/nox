package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/catalog"
	"github.com/nox-hq/nox/core/explain"
	"github.com/nox-hq/nox/core/findings"
)

// runWhy answers the eight questions for one finding, or for all of them.
//
// Separate from `nox explain`, which asks a language model to write prose. This
// reads only what the scan established, so the same finding always produces the
// same answers and every sentence traces to a claim, a capability state or a
// rule's own metadata. Both are useful; only one of them can be put in front of
// an auditor.
func runWhy(args []string) int {
	fs := flag.NewFlagSet("why", flag.ContinueOnError)
	var jsonOut bool
	var offline bool
	fs.BoolVar(&jsonOut, "json", false, "emit the explanation as JSON")
	fs.BoolVar(&offline, "offline", false, "guarantee zero network during the scan")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nox why [path] [--] [<fingerprint-prefix>|<rule-id>]

Answers, for each matching finding: what was observed, why it matters, what
supports it, what argues against it, what was not evaluated, the potential
impact, whether it affects this application, and what to do.

Deterministic: it reads only what the scan established. For model-written
prose, see `+"`nox explain`"+`.

Examples:
  nox why .                    every finding
  nox why . SEC-003            findings from one rule
  nox why . 65f66b3f2c17       one finding by fingerprint prefix

Flags:
`)
		fs.PrintDefaults()
	}
	// Split flags from positionals before parsing. Go's flag package stops at
	// the first non-flag argument, so `nox why . --offline` left --offline as a
	// positional and it was then read as a finding selector — the tool told the
	// user no finding matched "--offline". `nox show` splits first for the same
	// reason; this now does too.
	var flagArgs, positional []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			flagArgs = append(flagArgs, args[i])
			continue
		}
		positional = append(positional, args[i])
	}
	if err := fs.Parse(flagArgs); err != nil {
		return 2
	}

	target := "."
	selector := ""
	for _, a := range positional {
		if looksLikeSelector(a) {
			selector = a
			continue
		}
		target = a
	}

	res, err := nox.RunScanWithOptions(target, nox.ScanOptions{
		Offline: offline, RecordReasoning: true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: scan failed: %v\n", err)
		return 2
	}

	cat := catalog.Catalog()
	var out []explain.Explanation
	for _, f := range res.Findings.ActiveFindings() {
		if !matches(f, selector) {
			continue
		}
		subject := nox.SubjectForFinding(f)
		out = append(out, explain.Explain(explain.Inputs{
			Finding:  f,
			Ledger:   res.Reasoning.About(subject),
			Subject:  subject,
			Coverage: res.Coverage, Registry: res.Capabilities,
			Rule: cat[f.RuleID],
		}))
	}

	if len(out) == 0 {
		if selector == "" {
			fmt.Println("No active findings to explain.")
			return 0
		}
		fmt.Fprintf(os.Stderr, "no active finding matches %q\n", selector)
		return 1
	}

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 2
		}
		return 0
	}
	for i, e := range out {
		if i > 0 {
			fmt.Println()
		}
		printExplanation(e)
	}
	return 0
}

// looksLikeSelector distinguishes a rule ID or fingerprint prefix from a path.
// A path is the common case, so anything that could be one is treated as one.
func looksLikeSelector(a string) bool {
	if strings.ContainsAny(a, "/\\.") {
		return false
	}
	return strings.Contains(a, "-") || len(a) >= 8
}

func matches(f findings.Finding, selector string) bool {
	if selector == "" {
		return true
	}
	// findings.Addresses, not a local copy. The MCP server and this command
	// each had their own prefix match and they already disagreed about case,
	// so the same prefix resolved on one surface and not the other.
	return f.Addresses(selector)
}

func printExplanation(e explain.Explanation) {
	fmt.Printf("%s at %s\n", e.RuleID, e.Location)
	fmt.Printf("%s\n\n", strings.Repeat("─", 60))
	section("What was observed", []string{e.Observed})
	section("Why it matters", []string{e.WhyItMatters})
	section("What supports it", e.Supports)
	section("What argues against it", e.Against)
	section("What was not evaluated", e.NotEvaluated)
	section("Potential impact", []string{e.PotentialImpact})
	section("Does it affect this application", []string{e.AffectsThisApplication})
	section("What to do", []string{e.WhatToDo})
}

func section(title string, lines []string) {
	fmt.Printf("%s\n", title)
	for _, l := range lines {
		fmt.Printf("  %s\n", l)
	}
	fmt.Println()
}
