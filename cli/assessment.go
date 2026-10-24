package main

import (
	"fmt"
	"io"
	"os"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/assess"
	"github.com/nox-hq/nox/core/findings"
)

// scanAssessment is what the human-readable end of `nox scan` needs to know
// about the run. It exists so cli/main.go carries a call, not the logic; the
// assessment itself is built and rendered in core/assess.
type scanAssessment struct {
	result  *nox.ScanResult
	active  []findings.Finding
	target  string
	outDir  string
	formats []string
	offline bool
	verbose bool
}

// assessmentShown reports whether a run renders the assessment. Only a default
// scan does: --history looks at secrets in past commits and --staged at the
// index, and an account of the working tree's checks would overstate what
// either looked at. --quiet asks for no human summary at all.
func assessmentShown(quiet, staged, history bool) bool {
	return !quiet && !staged && !history
}

// findingsPath is where this run wrote findings.json, or "" when it did not,
// in the form the old [tip] lines used so a copied command still works.
func (a scanAssessment) findingsPath() string {
	for _, f := range a.formats {
		if f == "json" {
			return a.outDir + "/findings.json"
		}
	}
	return ""
}

// print writes the assessment to w. It replaces the [tip] lines: every command
// they offered is a next step here, offered only when it applies. --verbose
// lists every issue instead of the first assess.DefaultLimit.
func (a scanAssessment) print(w io.Writer) {
	in := assess.FromScan(a.result, a.active, a.target, a.findingsPath(), a.offline)
	// Mirrors the write rule in runScan: the inventory is written whenever it
	// holds a component, whatever --format says.
	if a.result != nil && a.result.AIInventory != nil && len(a.result.AIInventory.Components) > 0 {
		in.InventoryPath = a.outDir + "/ai.inventory.json"
	}
	opts := assess.RenderOptions{Limit: assess.DefaultLimit}
	if a.verbose {
		opts.Limit = 0
	}
	if err := assess.Render(w, assess.Build(in), opts); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not print the assessment: %v\n", err)
	}
}

// degradationsToPrint selects the [degraded] lines for stderr.
//
// A blocking degradation always prints, under --quiet too: a check that failed
// must never look like a clean scan. An advisory one (an installed plugin the
// project did not enable) is a choice, not a failure; when the assessment is
// shown it says so in plain words, so the full line, with every plugin name,
// moves behind --verbose. Without an assessment it prints as before, since it
// would otherwise not be said at all.
func degradationsToPrint(ds []nox.Degradation, assessmentShown, verbose bool) []nox.Degradation {
	if !assessmentShown || verbose {
		return ds
	}
	out := make([]nox.Degradation, 0, len(ds))
	for _, d := range ds {
		if d.Blocks() {
			out = append(out, d)
		}
	}
	return out
}
