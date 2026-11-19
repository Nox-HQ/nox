package deps

import (
	"reflect"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/vulnsource"
	"github.com/nox-hq/nox/core/applicability"
	"github.com/nox-hq/nox/core/capability"
)

func pySymbols(dist, status string, syms ...vulnsource.ChangedSymbol) *osvVuln {
	return &osvVuln{Symbols: []vulnsource.AffectedSymbols{{
		Ecosystem: "PyPI", Package: dist, Method: vulnsource.SymbolMethodPatchDiff, Status: status, Symbols: syms,
	}}}
}

// The proposition: a project that references a function the fix changed is
// raised, with the site as the witness and the weaker evidence named as such.
// Pillow is imported as PIL, so this is also the case a name match never saw.
func TestPyListedSymbolReferencedRaisesRelevance(t *testing.T) {
	src := tree(t, map[string]string{"app.py": "from PIL import Image\n\nimg = Image.open(path)\n"})
	ov := pySymbols("Pillow", "ok", exported("PIL.Image", "open"))
	meta := map[string]string{}
	got := raiseOnSourceListedSymbol(stuck(), meta, src, ov, Package{Name: "pillow", Ecosystem: "pypi"})
	if got.Reached != applicability.CallReachable || got.Outcome != applicability.Impacting {
		t.Fatalf("verdict = %+v, want an established call_reachable", got)
	}
	if meta["affected_symbol_evidence"] != "source_reference" || meta["affected_symbol_reached"] != "PIL.Image.open" ||
		!strings.HasSuffix(meta["affected_symbol_site"], "app.py:3") {
		t.Errorf("meta = %v", meta)
	}
	if !strings.Contains(sourceReferenceSentence(meta), "not established") {
		t.Error("the printed sentence must say what was not established")
	}
}

// A method is listed as Class.method; a call through the class is a reference.
func TestPyListedMethodThroughItsClass(t *testing.T) {
	src := tree(t, map[string]string{"app.py": "from rest_framework.parsers import JSONParser\nJSONParser.parse(stream)\n"})
	ov := pySymbols("djangorestframework", "ok", exported("rest_framework.parsers", "JSONParser.parse"))
	meta := map[string]string{}
	got := raiseOnSourceListedSymbol(stuck(), meta, src, ov, Package{Name: "djangorestframework", Ecosystem: "pypi"})
	if got.Outcome != applicability.Impacting || meta["affected_symbol_reached"] != "rest_framework.parsers.JSONParser.parse" {
		t.Fatalf("verdict = %+v meta = %v", got, meta)
	}
}

// THE rule: nothing that is not a positive reference may change the verdict.
func TestPyListedSymbolNeverLowersOrInventsAnything(t *testing.T) {
	pkg := Package{Name: "pillow", Ecosystem: "pypi"}
	uses := "from PIL import Image\nImage.open(p)\n"
	cases := map[string]struct {
		src map[string]string
		ov  *osvVuln
	}{
		"another function is used":     {map[string]string{"a.py": uses}, pySymbols("Pillow", "ok", exported("PIL.Image", "new"))},
		"symbol has no module":         {map[string]string{"a.py": uses}, pySymbols("Pillow", "ok", vulnsource.ChangedSymbol{Name: "open"})},
		"inconclusive carries nothing": {map[string]string{"a.py": uses}, pySymbols("Pillow", "inconclusive", exported("PIL.Image", "open"))},
		"only a test uses it":          {map[string]string{"test_a.py": uses}, pySymbols("Pillow", "ok", exported("PIL.Image", "open"))},
		"another distribution's":       {map[string]string{"a.py": uses}, pySymbols("Pillow-SIMD", "ok", exported("PIL.Image", "open"))},
		"no python was read":           {map[string]string{"a.js": "require('PIL')"}, pySymbols("Pillow", "ok", exported("PIL.Image", "open"))},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got := raiseOnSourceListedSymbol(stuck(), map[string]string{}, tree(t, c.src), c.ov, pkg)
			if !reflect.DeepEqual(got, stuck()) {
				t.Errorf("verdict changed to %+v", got)
			}
		})
	}
	refuted := applicability.Refuted(applicability.AffectedVersion, applicability.SymbolUsed, capability.Negative, []string{"x"})
	src := tree(t, map[string]string{"a.py": uses})
	if got := raiseOnSourceListedSymbol(refuted, map[string]string{}, src, pySymbols("Pillow", "ok", exported("PIL.Image", "open")), pkg); got.Outcome != applicability.NotImpacting {
		t.Errorf("a refutation was overturned: %+v", got)
	}
}

// The analysis of the package's own files names the modules it ships. A
// project that imports one of them uses the distribution, whatever its name:
// Pillow as PIL, PyJWT as jwt.
func TestPyImportNameFromTheAnalysisClimbsSymbolUsed(t *testing.T) {
	ov := pySymbols("PyJWT", "ok", exported("jwt.api_jwt", "decode"))
	pkg := Package{Name: "pyjwt", Ecosystem: "pypi"}
	src := tree(t, map[string]string{"auth.py": "import jwt\n"})
	v := applicabilityFor(pkg, ov, nil, false, src, nil, "")
	if v.Reached != applicability.SymbolUsed || v.StoppedAt != applicability.CallReachable {
		t.Fatalf("verdict = %+v, want symbol_used established", v)
	}
	if got := pyImportNames(ov, pkg.Name); len(got) != 1 || got[0] != "jwt" {
		t.Errorf("pyImportNames = %v, want [jwt]", got)
	}
	// Not imported: nothing changes.
	src = tree(t, map[string]string{"auth.py": "import os\n"})
	if v := applicabilityFor(pkg, ov, nil, false, src, nil, ""); v.Reached != applicability.AffectedVersion {
		t.Errorf("verdict = %+v, want unchanged", v)
	}
}
