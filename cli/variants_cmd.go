package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/analyzers/variants"
	"github.com/nox-hq/nox/core/findings"
)

// runVariants scans the target for code matching the root-cause pattern of a
// known CVE ("variants" of a published vulnerability reproduced in first-party
// code). With a CVE id argument it reports only that CVE's variants; with
// --list it prints the known signatures without scanning.
func runVariants(args []string) int {
	fs := flag.NewFlagSet("variants", flag.ContinueOnError)
	var listOnly bool
	fs.BoolVar(&listOnly, "list", false, "list the known CVE-variant signatures and exit")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: nox variants [--list] [CVE-ID] [path]")
		fmt.Fprintln(os.Stderr, "\nDetect first-party code that reproduces the root cause of a known CVE.")
		fmt.Fprintln(os.Stderr, "Deterministic and offline. Examples:")
		fmt.Fprintln(os.Stderr, "  nox variants .                 scan the current tree for all known CVE variants")
		fmt.Fprintln(os.Stderr, "  nox variants CVE-2021-44228 .  scan only for Log4Shell-style variants")
		fmt.Fprintln(os.Stderr, "  nox variants --list            list the known signatures")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Separate an optional CVE filter from the target path.
	var cveFilter, target string
	for _, a := range fs.Args() {
		if strings.HasPrefix(strings.ToUpper(a), "CVE-") {
			cveFilter = strings.ToUpper(a)
			continue
		}
		target = a
	}
	if target == "" {
		target = "."
	}

	if listOnly {
		return listVariantSignatures()
	}

	result, err := nox.RunScan(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nox variants: %v\n", err)
		return 1
	}

	var matches []findings.Finding
	all := result.Findings.Findings()
	for i := range all {
		if !strings.HasPrefix(all[i].RuleID, "VARIANT-") {
			continue
		}
		if cveFilter != "" && !strings.EqualFold(all[i].Metadata["cve"], cveFilter) {
			continue
		}
		matches = append(matches, all[i])
	}

	if len(matches) == 0 {
		if cveFilter != "" {
			fmt.Printf("No %s variants found in %s.\n", cveFilter, target)
		} else {
			fmt.Printf("No known CVE variants found in %s.\n", target)
		}
		return 0
	}

	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Metadata["cve"] != matches[j].Metadata["cve"] {
			return matches[i].Metadata["cve"] < matches[j].Metadata["cve"]
		}
		return matches[i].Location.FilePath < matches[j].Location.FilePath
	})
	fmt.Printf("[variants] %d CVE-variant finding(s):\n", len(matches))
	for i := range matches {
		m := &matches[i]
		fmt.Printf("  %s  %s:%d  [%s] %s\n",
			m.Metadata["cve"], m.Location.FilePath, m.Location.StartLine, m.Severity, m.Message)
	}
	return 1
}

func listVariantSignatures() int {
	rules := variants.NewAnalyzer().Rules().Rules()
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	fmt.Println("Known CVE-variant signatures:")
	for _, r := range rules {
		fmt.Printf("  %-12s %-16s %s\n", r.ID, r.Metadata["cve"], r.Description)
	}
	return 0
}
