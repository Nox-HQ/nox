package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nox-hq/nox/core/compliance/iso27001"
	"github.com/nox-hq/nox/core/git"
)

const complianceUsage = `Usage: nox compliance iso27001 [dir] [flags]

Prepares supporting material for an ISO/IEC 27001:2022 assessment from the
outputs of a scan you already ran (findings.json, an SBOM, ai.inventory.json).
It does not scan, does not touch the network, and never states that a control
is met: a scan can supply technical evidence, and this names what that evidence
does not show, plus the organizational evidence a repository cannot hold.

Run "nox scan . --format json,cdx" first. Then:

  nox compliance iso27001 .

Writes iso27001.md (for a reviewer) and iso27001.json (for tooling) to --out.

Flags:
`

// runCompliance implements "nox compliance".
func runCompliance(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(os.Stderr, "Usage: nox compliance <framework> [dir] [flags]\n\nFrameworks:\n  iso27001   ISO/IEC 27001:2022 Annex A technical evidence\n")
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	if args[0] != "iso27001" {
		fmt.Fprintf(os.Stderr, "error: unknown framework %q (available: iso27001)\n", args[0])
		return 2
	}
	return runComplianceISO27001(args[1:])
}

func runComplianceISO27001(args []string) int {
	fs := flag.NewFlagSet("compliance iso27001", flag.ContinueOnError)
	var findingsPath, sbomPath, aiPath, outDir, repoDir string
	var jsonOut, noWrite bool
	fs.StringVar(&findingsPath, "findings", "", "path to findings.json (default: <dir>/findings.json)")
	fs.StringVar(&sbomPath, "sbom", "", "path to a CycloneDX or SPDX JSON SBOM (default: <dir>/sbom.cdx.json, then sbom.spdx.json)")
	fs.StringVar(&aiPath, "ai-inventory", "", "path to ai.inventory.json (default: <dir>/ai.inventory.json)")
	fs.StringVar(&repoDir, "repo", "", "repository to read the commit from when scan outputs are kept elsewhere (default: <dir>)")
	fs.StringVar(&outDir, "out", "compliance", "directory to write iso27001.md and iso27001.json to")
	fs.BoolVar(&jsonOut, "json", false, "print the assessment as JSON to stdout instead of the summary; writes no files")
	fs.BoolVar(&noWrite, "no-write", false, "print the summary only; write no files")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, complianceUsage)
		fs.PrintDefaults()
	}
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return 2
	}
	dir := "."
	if len(pos) > 0 {
		dir = pos[0]
	}

	in, err := loadISO27001Input(dir, repoDir, findingsPath, sbomPath, aiPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	a := iso27001.Assess(in)

	if jsonOut {
		data, err := a.JSON()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 2
		}
		_, _ = os.Stdout.Write(data)
		return 0
	}

	fmt.Print(a.Terminal())
	if noWrite {
		return 0
	}
	return writeISO27001(a, outDir)
}

func writeISO27001(a iso27001.Assessment, outDir string) int {
	data, err := a.JSON()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error: creating %s: %v\n", outDir, err)
		return 2
	}
	files := []struct {
		name string
		body []byte
	}{
		{"iso27001.md", []byte(a.Markdown())},
		{"iso27001.json", data},
	}
	for _, f := range files {
		path := filepath.Join(outDir, f.name)
		if err := os.WriteFile(path, f.body, 0o644); err != nil { //nolint:gosec // a report meant to be shared
			fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", path, err)
			return 2
		}
		fmt.Printf("[report] wrote %s\n", path)
	}
	return 0
}

// loadISO27001Input reads the scan outputs an assessment is built from. Only
// findings.json is required; an absent SBOM or AI inventory is recorded in the
// assessment as a gap rather than treated as an error, because a scan scoped
// away from dependencies legitimately has none.
func loadISO27001Input(dir, repoDir, findingsPath, sbomPath, aiPath string) (iso27001.Input, error) {
	var in iso27001.Input
	in.NoxVersion = version

	if findingsPath == "" {
		findingsPath = filepath.Join(dir, "findings.json")
	}
	raw, err := os.ReadFile(findingsPath) //nolint:gosec // caller-supplied scan artifact
	if err != nil {
		if os.IsNotExist(err) {
			return in, fmt.Errorf("no scan output at %s; run `nox scan %s --format json,cdx` first, then run this again", findingsPath, dir)
		}
		return in, err
	}
	rep, art, err := iso27001.ParseFindings(filepath.Base(findingsPath), raw)
	if err != nil {
		return in, err
	}
	in.Report = rep
	in.Artifacts = append(in.Artifacts, art)

	if sbomPath == "" {
		sbomPath = firstExisting(filepath.Join(dir, "sbom.cdx.json"), filepath.Join(dir, "sbom.spdx.json"))
	}
	if sbomPath != "" {
		data, err := os.ReadFile(sbomPath) //nolint:gosec // caller-supplied scan artifact
		if err != nil {
			return in, err
		}
		s, sa, err := iso27001.ParseSBOM(filepath.Base(sbomPath), data)
		if err != nil {
			return in, err
		}
		in.SBOM = s
		in.Artifacts = append(in.Artifacts, sa)
	}

	if aiPath == "" {
		aiPath = firstExisting(filepath.Join(dir, "ai.inventory.json"))
	}
	if aiPath != "" {
		data, err := os.ReadFile(aiPath) //nolint:gosec // caller-supplied scan artifact
		if err != nil {
			return in, err
		}
		a, aa, err := iso27001.ParseAIInventory(filepath.Base(aiPath), data)
		if err != nil {
			return in, err
		}
		in.AI = a
		in.Artifacts = append(in.Artifacts, aa)
	}

	// The revision is best-effort provenance. Outside a git repository the
	// assessment simply omits it.
	if repoDir == "" {
		repoDir = dir
	}
	if c, err := git.HeadCommit(repoDir); err == nil {
		in.Commit = c
	}
	return in, nil
}

func firstExisting(paths ...string) string {
	for _, p := range paths {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}
