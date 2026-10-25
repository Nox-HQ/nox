package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/advisory"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/fsutil"
	"github.com/nox-hq/nox/core/report"
)

const advisoriesUsage = `nox advisories — decide what to do about a newly disclosed dependency advisory

Usage:
  nox advisories [flags]

Reads a findings.json written by ` + "`nox scan`" + ` and, for each dependency
advisory in it, decides whether it is new, how relevant it is to this
application, and what the configured policy says to do:

  report     tell someone (job summary, issue); nothing else
  prepare    also open a remediation pull request with the planned upgrade
  remediate  also permit auto-merge, only for safe upgrades, only when the
             repository's own required checks pass (branch protection decides)

The policy comes from the .nox.yaml advisories block and defaults to report.
Nothing is ever merged by this command; it says whether a merge is permitted.

"New" means active in this scan and absent from --previous, the findings.json of
the last run. Advisories already baselined or waived through VEX are shown as
waived, never as new. With no --previous the first run reports everything and
acts on nothing.

An advisory nox could not place against the code (relevance undetermined) is
treated as possibly affecting it. Only an advisory shown not to affect the
build is held at report, and the reason is printed either way.

Flags:
  --input             findings.json to read (default "findings.json")
  --root              directory holding .nox.yaml (default ".")
  --previous          findings.json from the last scheduled run
  --policy            override the .nox.yaml policy (report, prepare, remediate)
  --format            text, json or markdown (default "text")
  --prepare-findings  write the findings behind the pull request to this file,
                      for ` + "`nox fix --input`" + `
  --markdown-out      also write the markdown report to this file (an issue body)
  --github            write step outputs and the job summary

Exit codes:
  0  decided
  1  decided, but the scan could not finish looking; nothing was acted on
  2  could not run (unreadable input, invalid policy)
`

func runAdvisories(args []string) int {
	fs := flag.NewFlagSet("advisories", flag.ContinueOnError)
	input := fs.String("input", "findings.json", "findings.json to read")
	root := fs.String("root", ".", "directory holding .nox.yaml")
	previous := fs.String("previous", "", "findings.json from the last scheduled run")
	policyFlag := fs.String("policy", "", "override the .nox.yaml policy")
	format := fs.String("format", "text", "text, json or markdown")
	prepareOut := fs.String("prepare-findings", "", "write the pull request's findings to this file")
	markdownOut := fs.String("markdown-out", "", "also write the markdown report to this file")
	github := fs.Bool("github", false, "write GitHub step outputs and job summary")
	fs.Usage = func() { fmt.Fprint(os.Stderr, advisoriesUsage) }
	if err := parseFlagsAnywhere(fs, args); err != nil {
		return 2
	}

	cfg, err := nox.LoadScanConfig(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading .nox.yaml: %v\n", err)
		return 2
	}
	settings := cfg.Advisories
	if *policyFlag != "" {
		settings.Policy = *policyFlag
	}
	pol, err := settings.Resolve()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	rep, err := report.LoadFindingsFileReport(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading %s: %v\n", *input, err)
		return 2
	}

	in := advisory.Input{Findings: rep.Findings, Policy: pol, Incomplete: advisory.IncompleteReason(rep.Meta.Degradations)}
	var warning string
	in.Previous, in.HavePrevious, warning = report.LoadPreviousFindings(*previous)
	if warning != "" {
		fmt.Fprintf(os.Stderr, "warning: %s\n", warning)
	}

	res := advisory.Evaluate(in)

	if *prepareOut != "" {
		if err := writePrepareFindings(*prepareOut, rep, res); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 2
		}
	}
	if *markdownOut != "" {
		if err := fsutil.AtomicWriteFile(*markdownOut, []byte(advisory.Markdown(res)), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 2
		}
	}
	if err := renderAdvisories(os.Stdout, *format, res); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	if *github {
		if err := writeAdvisoryGitHub(res); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 2
		}
	}
	if res.Incomplete != "" {
		return 1
	}
	return 0
}

func writePrepareFindings(path string, rep report.JSONReport, res advisory.Result) error {
	out := rep
	out.Findings = make([]findings.Finding, 0, len(res.Fixes))
	for _, i := range res.Fixes {
		out.Findings = append(out.Findings, rep.Findings[i])
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding %s: %w", path, err)
	}
	return fsutil.AtomicWriteFile(path, append(data, '\n'), 0o644)
}

func renderAdvisories(w io.Writer, format string, res advisory.Result) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	case "markdown":
		_, err := io.WriteString(w, advisory.Markdown(res))
		return err
	case "text":
		_, err := io.WriteString(w, advisory.Text(res))
		return err
	}
	return fmt.Errorf("--format %q is not text, json or markdown", format)
}

// writeAdvisoryGitHub appends step outputs and the job summary. Each is a plain
// file append, which is all the runner reads.
func writeAdvisoryGitHub(res advisory.Result) error {
	newN, _, _ := res.Counts()
	if out := os.Getenv("GITHUB_OUTPUT"); out != "" {
		lines := fmt.Sprintf("action=%s\nautomerge=%t\nnew-count=%d\nprepare-count=%d\nprevious-run=%t\nincomplete=%t\n",
			res.Action, res.AutoMerge, newN, len(res.Prepare), res.PreviousRun, res.Incomplete != "")
		if err := appendFile(out, lines); err != nil {
			return err
		}
	}
	if sum := os.Getenv("GITHUB_STEP_SUMMARY"); sum != "" {
		if err := appendFile(sum, advisory.Markdown(res)); err != nil {
			return err
		}
	}
	if res.Incomplete != "" {
		fmt.Printf("::error::nox advisories: scan incomplete (%s); nothing was acted on\n", res.Incomplete)
	}
	return nil
}

func appendFile(path, s string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644) //nolint:gosec // runner-provided path
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}
	if _, err := f.WriteString(s); err != nil {
		_ = f.Close()
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return f.Close()
}
