package deps

import (
	"testing"

	"github.com/nox-hq/nox-core/vulnsource"
	"github.com/nox-hq/nox/core/applicability"
	"github.com/nox-hq/nox/core/callgraph"
	"github.com/nox-hq/nox/core/capability"
)

const symModule = "example.com/vulnmod"
const symPkg = "example.com/vulnmod/pgp"

func symGraph(t *testing.T, call string) *callgraph.Graph {
	t.Helper()
	dir := goModule(t, map[string]string{
		"go.mod":  "module example.com/app\n\ngo 1.21\n",
		"main.go": "package main\n\nimport \"" + symPkg + "\"\n\nfunc main() { pgp." + call + "() }\n",
	})
	return callgraph.BuildGo(dir)
}

func noxSymbols(status string, names ...string) []vulnsource.AffectedSymbols {
	as := vulnsource.AffectedSymbols{Package: symModule, Method: vulnsource.SymbolMethodPatchDiff, Status: status}
	for _, n := range names {
		as.Symbols = append(as.Symbols, vulnsource.ChangedSymbol{Name: n, Package: symPkg, Confidence: "medium"})
	}
	return []vulnsource.AffectedSymbols{as}
}

func publisherSymbols(path string, names ...string) []osvAffected {
	aff := osvAffected{Package: osvPackage{Name: symModule}}
	aff.EcosystemSpecific.Imports = append(aff.EcosystemSpecific.Imports, osvImport{Path: path, Symbols: names})
	return []osvAffected{aff}
}

// The verdict the climb reached before any symbol was looked at: the affected
// package is not known (a GHSA record with no imports), so it stopped.
func stuck() applicability.Verdict {
	return applicability.Undeterminable(applicability.AffectedVersion, applicability.SymbolUsed, capability.Unknown)
}

// A call path that reaches a listed symbol raises relevance to a call path.
func TestAListedSymbolThatIsCalledRaisesRelevance(t *testing.T) {
	for name, ov := range map[string]*osvVuln{
		"nox_symbols (patch-diff)":      {Symbols: noxSymbols(vulnsource.SymbolStatusOK, "ReadMessage")},
		"publisher's imports[].symbols": {Affected: publisherSymbols(symPkg, "ReadMessage")},
	} {
		t.Run(name, func(t *testing.T) {
			meta := map[string]string{}
			got := raiseOnListedSymbol(stuck(), meta, symGraph(t, "ReadMessage"), ov, symModule)
			if got.Outcome != applicability.Impacting || got.Reached != applicability.CallReachable || len(got.Path) == 0 {
				t.Fatalf("verdict = %+v, want impacting at call_reachable with a witness", got)
			}
			if meta["affected_symbol_reached"] != symPkg+".ReadMessage" {
				t.Errorf("metadata = %v", meta)
			}
		})
	}
}

// THE rule: the absence of a listed-symbol call never lowers anything.
func TestAbsenceOfAListedSymbolCallNeverLowersRelevance(t *testing.T) {
	ov := &osvVuln{Symbols: noxSymbols(vulnsource.SymbolStatusOK, "Decrypt")}
	g := symGraph(t, "ReadMessage") // calls the package, not the listed symbol

	// From each starting point, the verdict must come back unchanged.
	for name, v := range map[string]applicability.Verdict{
		"undetermined":        stuck(),
		"already a call path": applicability.Established(applicability.CallReachable, []string{"main"}),
		"symbol used":         applicability.Undeterminable(applicability.SymbolUsed, applicability.CallReachable, capability.Unknown),
	} {
		meta := map[string]string{}
		got := raiseOnListedSymbol(v, meta, g, ov, symModule)
		if got.Outcome != v.Outcome || got.Reached != v.Reached || got.StoppedAt != v.StoppedAt {
			t.Errorf("%s: verdict changed from %+v to %+v", name, v, got)
		}
		if len(meta) != 0 {
			t.Errorf("%s: nothing was reached, nothing may be recorded: %v", name, meta)
		}
	}
}

// An inconclusive analysis lists nothing, and a nil graph finds nothing.
func TestOnlyUsableSymbolsAreSearchedFor(t *testing.T) {
	g := symGraph(t, "ReadMessage")
	for name, ov := range map[string]*osvVuln{
		"inconclusive":      {Symbols: noxSymbols("inconclusive", "ReadMessage")},
		"another module's":  {Symbols: []vulnsource.AffectedSymbols{{Package: "example.com/other", Status: "ok", Symbols: []vulnsource.ChangedSymbol{{Name: "ReadMessage", Package: symPkg}}}}},
		"no symbols at all": {},
	} {
		if got := raiseOnListedSymbol(stuck(), map[string]string{}, g, ov, symModule); got.Outcome == applicability.Impacting {
			t.Errorf("%s raised relevance", name)
		}
	}
	if got := raiseOnListedSymbol(stuck(), map[string]string{}, nil, &osvVuln{Symbols: noxSymbols("ok", "ReadMessage")}, symModule); got.Outcome == applicability.Impacting {
		t.Error("no graph, no path")
	}
}

// A publisher's statement that the build does not link the affected package is
// not overridden by a hint from a patch analysis.
func TestAListedSymbolDoesNotOverrideARefutation(t *testing.T) {
	refuted := applicability.Refuted(applicability.AffectedVersion, applicability.SymbolUsed, capability.Negative, []string{"the build links no package under x"})
	ov := &osvVuln{Symbols: noxSymbols(vulnsource.SymbolStatusOK, "ReadMessage")}
	meta := map[string]string{}
	got := raiseOnListedSymbol(refuted, meta, symGraph(t, "ReadMessage"), ov, symModule)
	if got.Outcome != applicability.NotImpacting {
		t.Fatalf("a refutation was overridden: %+v", got)
	}
}

// The publisher's list is attributed to the advisory, nox_symbols to nox.
func TestListedSymbolBasisIsRecorded(t *testing.T) {
	meta := map[string]string{}
	raiseOnListedSymbol(stuck(), meta, symGraph(t, "ReadMessage"), &osvVuln{Affected: publisherSymbols(symPkg, "ReadMessage")}, symModule)
	if meta["affected_symbol_basis"] != "advisory" {
		t.Errorf("basis = %q", meta["affected_symbol_basis"])
	}
	meta = map[string]string{}
	raiseOnListedSymbol(stuck(), meta, symGraph(t, "ReadMessage"), &osvVuln{Symbols: noxSymbols("ok", "ReadMessage")}, symModule)
	if meta["affected_symbol_basis"] != "nox_symbols" {
		t.Errorf("basis = %q", meta["affected_symbol_basis"])
	}
}
