package core

import (
	"context"
	"fmt"
	"strings"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/parallel"
)

// degradeGeneratedReport marks files a scan did not read because nox wrote
// them. Advisory: the operator did not ask for nox's own reports to be
// scanned, and a build must not fail because a results.sarif is committed.
const degradeGeneratedReport = degrade.Kind("generated_report")

// maxNamedReports bounds how many skipped paths the degradation spells out.
// The count is always exact; past this many, the detail says how many more.
const maxNamedReports = 20

// skipGeneratedReports removes reports nox wrote from the discovered set, and
// records every one it removed.
//
// It runs on the discovered set rather than inside the walker so that the skip
// has somewhere to be reported: the walker has no degradation channel, and a
// file removed from a scan without a trace is the failure this project
// guards against everywhere else. Every adapter — CLI, MCP, LSP — reaches it
// through discoverArtifacts, so none of them can scan a report the others skip.
//
// See discovery.GeneratedReport for what counts as a report and why the
// decision is made on content rather than on a name or a path.
func skipGeneratedReports(artifacts []discovery.Artifact, deg *degrade.Degradations) []discovery.Artifact {
	// One open and one prefix read per candidate file, spread across the cores;
	// results come back in input order, so the kept set and the degradation
	// text are what a sequential loop would produce. The function never fails,
	// so neither does Map.
	kinds, _ := parallel.Map(context.Background(), len(artifacts), func(i int) (string, error) {
		kind, _ := discovery.GeneratedReport(artifacts[i].AbsPath)
		return kind, nil
	})
	kept := artifacts[:0:0]
	var skipped []string
	for i, a := range artifacts {
		if kinds[i] != "" {
			skipped = append(skipped, fmt.Sprintf("%s (%s)", a.Path, kinds[i]))
			continue
		}
		kept = append(kept, a)
	}
	if len(skipped) == 0 {
		return artifacts
	}
	named := skipped
	more := ""
	if len(named) > maxNamedReports {
		more = fmt.Sprintf(", and %d more", len(named)-maxNamedReports)
		named = named[:maxNamedReports]
	}
	deg.AddAdvisory(degradeGeneratedReport,
		fmt.Sprintf("%d file(s) not scanned because nox wrote them: %s%s",
			len(skipped), strings.Join(named, ", "), more),
		"a nox report holds nox's own rule text and finding messages, which match the rules they "+
			"describe when read as source, and whatever of the project's they quote is reported where "+
			"the project has it. Another tool's "+
			"report, or one that merges a nox run with another tool's, is still scanned")
	return kept
}
