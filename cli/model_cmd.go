package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nox-hq/nox/core/threatmodel"
)

const modelUsage = `Usage: nox model [dir] [flags]

Builds a threat model from the outputs of a scan you already ran (findings.json,
an SBOM, ai.inventory.json): the elements nox can evidence (routes and their
authentication middleware, AI agents and their tools, MCP servers, data stores,
external services, the deployment surface), the data flows and trust boundaries
between them, a STRIDE table with the evidence for each element and category,
the questions the gaps raise, and what nox cannot see.

It does not scan, does not touch the network, and never says that a threat is
absent or handled: a category with no evidence is "not evidenced either way".

Run "nox scan . --format json,cdx" first. Then:

  nox model .
  nox model . --previous last-month/model.json

Writes model.md (for people) and model.json (for tooling) to --out.

Flags:
`

// runModel implements "nox model".
func runModel(args []string) int {
	fs := flag.NewFlagSet("model", flag.ContinueOnError)
	var p threatmodel.Paths
	var outDir, previous string
	var jsonOut, noWrite, noDiagram bool
	fs.StringVar(&p.Findings, "findings", "", "path to findings.json (default: <dir>/findings.json)")
	fs.StringVar(&p.SBOM, "sbom", "", "path to a CycloneDX or SPDX JSON SBOM (default: <dir>/sbom.cdx.json, then sbom.spdx.json)")
	fs.StringVar(&p.Inventory, "ai-inventory", "", "path to ai.inventory.json (default: <dir>/ai.inventory.json)")
	fs.StringVar(&p.Repo, "repo", "", "repository to read the commit from when scan outputs are kept elsewhere (default: <dir>)")
	fs.StringVar(&outDir, "out", "threat-model", "directory to write model.md and model.json to")
	fs.StringVar(&previous, "previous", "", "an earlier model.json: report the elements, flows, boundaries and STRIDE cells that changed since")
	fs.BoolVar(&jsonOut, "json", false, "print the model as JSON to stdout instead of the summary; writes no files")
	fs.BoolVar(&noWrite, "no-write", false, "print the summary only; write no files")
	fs.BoolVar(&noDiagram, "no-diagram", false, "leave the Mermaid data-flow diagram out of model.md")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, modelUsage)
		fs.PrintDefaults()
	}
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return 2
	}
	p.Dir = "."
	if len(pos) > 0 {
		p.Dir = pos[0]
	}

	in, err := threatmodel.Load(p, version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	m, err := threatmodel.BuildAgainst(in, previous)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	if jsonOut {
		data, err := m.JSON()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 2
		}
		_, _ = os.Stdout.Write(data)
		return 0
	}
	fmt.Print(m.Terminal())
	if noWrite {
		return 0
	}
	return writeModel(m, outDir, !noDiagram)
}

func writeModel(m threatmodel.Model, outDir string, diagram bool) int {
	data, err := m.JSON()
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
		{"model.md", []byte(m.Markdown(diagram))},
		{"model.json", data},
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
