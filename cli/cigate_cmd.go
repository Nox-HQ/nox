package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nox-hq/nox/core/policy"
	"github.com/nox-hq/nox/core/report"
)

const ciGateUsage = `nox ci-gate — decide whether a scan should fail a build

Usage:
  nox ci-gate [flags]

Reads a findings.json written by ` + "`nox scan`" + ` and applies the CI gate:
a missing artifact, a required analyzer that did not run, a code-security
family at any severity, and net-new critical/high above a committed baseline.

The gate is deliberately asymmetric about baselines. A repository with none is
report-only, so adopting the gate never breaks a build that was passing. A
repository whose baseline matches NOTHING is an error — that is fingerprint
drift, not a clean repository, and treating it like an absent baseline silently
deletes the gate.

Flags:
  --input     findings.json to read (default "findings.json")
  --baseline  path the baseline would be at (default ".nox/baseline.json")
  --strict    gate a repository that has committed no baseline
  --github    emit ::error:: / ::warning:: annotations

Exit codes:
  0  the gate passed
  1  the gate failed
  2  the gate could not run
`

// runCIGate is the invocation the shared CI workflow's bash shrinks to.
//
// All of this was jq: four checks, each with a paragraph of reasoning in a YAML
// comment where no test could reach it. Every consumer that was not that
// workflow either re-implemented the checks or did without — and the one with a
// real incident behind it, the dead baseline, is precisely the kind of thing
// that is easy to leave out of a re-implementation because its symptom is a
// green check.
func runCIGate(args []string) int {
	fs := flag.NewFlagSet("ci-gate", flag.ContinueOnError)
	input := fs.String("input", "findings.json", "findings.json to read")
	baseline := fs.String("baseline", filepath.Join(".nox", "baseline.json"), "baseline path")
	strict := fs.Bool("strict", false, "gate a repository with no committed baseline")
	github := fs.Bool("github", false, "emit GitHub Actions annotations")
	fs.Usage = func() { fmt.Fprint(os.Stderr, ciGateUsage) }
	if err := fs.Parse(args); err != nil {
		return 2
	}

	in := policy.CIGate{Strict: *strict}
	if _, err := os.Stat(*baseline); err == nil {
		in.BaselineExists = true
	}

	rep, err := report.LoadFindingsFileReport(*input)
	if err == nil {
		in.FindingsWritten = true
		in.Findings = rep.Findings
		for _, d := range rep.Meta.Degradations {
			in.Degradations = append(in.Degradations, policy.Degradation{
				Kind: d.Kind, Detail: d.Detail, Impact: d.Impact, Advisory: d.Advisory,
			})
		}
	}

	r := policy.EvaluateCI(in)
	for _, w := range r.Warnings {
		if *github {
			fmt.Printf("::warning::%s\n", w)
			continue
		}
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}
	for _, e := range r.Errors {
		if *github {
			fmt.Printf("::error::%s\n", e)
			continue
		}
		fmt.Fprintf(os.Stderr, "error: %s\n", e)
	}
	// Printed whatever the decision, so a green run says what it evaluated
	// rather than only that it passed.
	fmt.Printf("net-new critical/high: %d (baselined: %d, code-security: %d)\n",
		r.NetNewHigh, r.Baselined, r.CodeSecurity)

	if !r.Pass {
		return 1
	}
	return 0
}
