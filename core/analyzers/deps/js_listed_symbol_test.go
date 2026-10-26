package deps

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/vulnsource"
	"github.com/nox-hq/nox/core/applicability"
)

const jsModule = "nodemailer"

func jsSymbols(status string, syms ...vulnsource.ChangedSymbol) *osvVuln {
	return &osvVuln{Symbols: []vulnsource.AffectedSymbols{{
		Ecosystem: "npm", Package: jsModule, Method: vulnsource.SymbolMethodPatchDiff, Status: status, Symbols: syms,
	}}}
}

func exported(spec, name string) vulnsource.ChangedSymbol {
	return vulnsource.ChangedSymbol{Name: name, Package: spec, Confidence: "low"}
}

// The proposition: a project that references an export the fix changed is
// raised to a call path, with the site as the witness and the weaker evidence
// named as such.
func TestJSListedSymbolReferencedRaisesRelevance(t *testing.T) {
	src := tree(t, map[string]string{"app.js": "const { parseAddresses } = require('nodemailer/lib/addressparser');\nparseAddresses(x);"})
	ov := jsSymbols("ok", exported("nodemailer/lib/addressparser", "parseAddresses"))
	meta := map[string]string{}
	got := raiseOnJSListedSymbol(stuck(), meta, src, ov, Package{Name: jsModule, Ecosystem: "npm"})
	if got.Reached != applicability.CallReachable || got.Outcome != applicability.Impacting {
		t.Fatalf("verdict = %+v, want an established call_reachable", got)
	}
	if meta["affected_symbol_evidence"] != "source_reference" || meta["affected_symbol_basis"] != "nox_symbols" ||
		meta["affected_symbol_reached"] != "nodemailer/lib/addressparser.parseAddresses" {
		t.Errorf("meta = %v", meta)
	}
	if !strings.Contains(sourceReferenceSentence(meta), "not established") {
		t.Error("the printed sentence must say what was not established")
	}
}

// THE rule: nothing that is not a positive reference may change the verdict.
func TestJSListedSymbolNeverLowersOrInventsAnything(t *testing.T) {
	pkg := Package{Name: jsModule, Ecosystem: "npm"}
	imports := "const nm = require('nodemailer');\nnm.createTransport();"
	cases := map[string]struct {
		src map[string]string
		ov  *osvVuln
		pkg Package
	}{
		"another export is used":       {map[string]string{"a.js": imports}, jsSymbols("ok", exported("nodemailer", "sendMail")), pkg},
		"internal symbol has no spec":  {map[string]string{"a.js": imports}, jsSymbols("ok", vulnsource.ChangedSymbol{Name: "createTransport"}), pkg},
		"inconclusive carries nothing": {map[string]string{"a.js": imports}, jsSymbols("inconclusive", exported("nodemailer", "createTransport")), pkg},
		"only a test uses it":          {map[string]string{"a.test.js": imports}, jsSymbols("ok", exported("nodemailer", "createTransport")), pkg},
		"another package's symbol":     {map[string]string{"a.js": imports}, jsSymbols("ok", exported("othermailer", "createTransport")), pkg},
		"a different ecosystem":        {map[string]string{"a.js": imports}, jsSymbols("ok", exported("nodemailer", "createTransport")), Package{Name: jsModule, Ecosystem: "PyPI"}},
		"no javascript was read":       {map[string]string{"a.py": "import nodemailer"}, jsSymbols("ok", exported("nodemailer", "createTransport")), pkg},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			meta := map[string]string{}
			got := raiseOnJSListedSymbol(stuck(), meta, tree(t, c.src), c.ov, c.pkg)
			if got.Reached != stuck().Reached || got.Outcome != stuck().Outcome || len(meta) != 0 {
				t.Errorf("verdict %+v meta %v: nothing may change", got, meta)
			}
		})
	}
	// It must also never override a refutation.
	refuted := applicability.Refuted(applicability.AffectedVersion, applicability.SymbolUsed, "negative", []string{"x"})
	src := tree(t, map[string]string{"a.js": imports})
	if got := raiseOnJSListedSymbol(refuted, map[string]string{}, src, jsSymbols("ok", exported("nodemailer", "createTransport")), pkg); got.Outcome != applicability.NotImpacting {
		t.Errorf("a refutation was overridden: %+v", got)
	}
	// Nor a nil source index.
	if got := raiseOnJSListedSymbol(stuck(), map[string]string{}, nil, jsSymbols("ok", exported("nodemailer", "createTransport")), pkg); got.Outcome == applicability.Impacting {
		t.Error("nil source must not raise")
	}
}
