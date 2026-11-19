package core

import (
	"testing"

	"github.com/nox-hq/nox/core/callgraph"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/taint/engine"
)

// Pillow is imported as PIL. The call graph records calls by the name the
// source imports, so a climb that asked only for "pillow" never found the call
// into PIL. The deps analyzer records the distribution's import names, from the
// analysis of its own files, and the climb asks for those too.
func TestDependencyClimbsThroughAnImportName(t *testing.T) {
	src := "from PIL import Image\n\ndef thumb(p):\n    return Image.open(p)\n\nif __name__ == \"__main__\":\n    thumb(1)\n"
	b := callgraph.NewSourceBuilder()
	b.Add("app.py", []byte(src), engine.ExtractUnits("app.py", lexctx.LangFromPath("app.py"), []byte(src)))
	g := b.Build(nil)

	for name, c := range map[string]struct {
		importNames string
		want        string
	}{
		"with the import name":    {"PIL", "call_reachable"},
		"without the import name": {"", "symbol_used"},
	} {
		t.Run(name, func(t *testing.T) {
			fs := findings.NewFindingSet()
			meta := map[string]string{
				"ecosystem": "pypi", "package": "pillow",
				"applicability": "undetermined", "applicability_reached": "symbol_used",
				"applicability_stopped_at": "call_reachable", "applicability_because": "unsupported",
			}
			if c.importNames != "" {
				meta["import_names"] = c.importNames
			}
			fs.Add(findings.Finding{RuleID: "VULN-001", Message: "Known vulnerability", Metadata: meta})
			raiseDependencyReachability(fs, g)
			got := fs.Findings()[0].Metadata
			if got["applicability_reached"] != c.want {
				t.Errorf("reached %q, want %q; metadata %v", got["applicability_reached"], c.want, got)
			}
		})
	}
}
