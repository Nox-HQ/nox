package deps

import (
	"reflect"
	"testing"

	"github.com/nox-hq/nox-core/vulnsource"
)

func rec(id string, sameAs []string, sev string, aliases ...string) vulnsource.Record {
	return vulnsource.Record{
		ID: id, Aliases: aliases, SameAs: sameAs,
		DatabaseSpecific: vulnsource.DatabaseSpecific{Severity: sev},
		Provenance:       []vulnsource.Provenance{{Source: "osv.dev", Via: "live"}},
	}
}

func ids(rs []vulnsource.Record) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.ID)
	}
	return out
}

func TestCollapseSameAs_OneVulnerabilityUnderTwoIdsIsOne(t *testing.T) {
	in := []vulnsource.Record{
		rec("GO-2026-1", []string{"GHSA-a"}, "", "GHSA-a"),
		rec("GHSA-a", []string{"GO-2026-1"}, "", "GO-2026-1", "CVE-1"),
	}
	got := mustCollapse(in)
	if len(got) != 1 {
		t.Fatalf("got %v", ids(got))
	}
	if !reflect.DeepEqual(got[0].Aliases, []string{"CVE-1", "GO-2026-1"}) {
		t.Errorf("aliases = %v, want every other name kept", got[0].Aliases)
	}
}

// Collapsing must never lower what is reported: the surviving record is the
// more severe one even when its id sorts later.
func TestCollapseSameAs_NeverLowersSeverity(t *testing.T) {
	in := []vulnsource.Record{
		rec("GHSA-a", []string{"GO-9"}, "CRITICAL", "GO-9"),
		rec("GO-9", []string{"GHSA-a"}, "LOW", "GHSA-a"),
	}
	for _, order := range [][]int{{0, 1}, {1, 0}} {
		got := mustCollapse([]vulnsource.Record{in[order[0]], in[order[1]]})
		if len(got) != 1 || got[0].ID != "GHSA-a" || got[0].DatabaseSpecific.Severity != "CRITICAL" {
			t.Errorf("order %v: got %+v", order, got)
		}
	}
}

func TestCollapseSameAs_TransitiveAndIndependent(t *testing.T) {
	in := []vulnsource.Record{
		rec("A", []string{"B"}, ""), rec("B", []string{"A", "C"}, ""), rec("C", []string{"B"}, ""),
		rec("OTHER", nil, ""),
	}
	got := mustCollapse(in)
	if !reflect.DeepEqual(ids(got), []string{"A", "OTHER"}) {
		t.Errorf("got %v, want [A OTHER]", ids(got))
	}
}

// Without nox_same_as (OSV.dev directly, or an older service) records join by
// the rule the service uses for nox_same_as: two records in one answer that
// share a name, their id or an alias, are one vulnerability. Before, a scan
// with NOX Intelligence off reported each GO-/GHSA- pair twice: 2,201 Go
// findings for 947 vulnerabilities across 8 real repositories.
func TestCollapseSameAs_SharedNamesJoinWithoutSameAs(t *testing.T) {
	in := []vulnsource.Record{
		rec("GO-1", nil, "", "CVE-1", "GHSA-a"),
		rec("GHSA-a", nil, "HIGH", "CVE-1", "GO-1"),
		rec("GHSA-b", nil, "", "CVE-1"), // only the CVE in common: still the same vulnerability
		rec("GHSA-c", nil, "", "CVE-2"),
	}
	got := mustCollapse(in)
	if !reflect.DeepEqual(ids(got), []string{"GHSA-a", "GHSA-c"}) {
		t.Errorf("got %v, want [GHSA-a GHSA-c]", ids(got))
	}
}

// A record's own id is one of its names: an advisory listing another's id
// joins it even when the other lists nothing back.
func TestCollapseSameAs_AnIdNamedAsAnAliasJoins(t *testing.T) {
	in := []vulnsource.Record{rec("GO-1", nil, ""), rec("GHSA-a", nil, "", "GO-1")}
	if got := mustCollapse(in); len(got) != 1 {
		t.Errorf("got %v", ids(got))
	}
}

// When the source does send nox_same_as, its verdict stands: shared aliases do
// not join records it kept apart.
func TestCollapseSameAs_SameAsFromTheSourceIsAuthoritative(t *testing.T) {
	in := []vulnsource.Record{
		rec("GO-1", []string{"GHSA-a"}, "", "GHSA-a"),
		rec("GHSA-a", []string{"GO-1"}, "", "GO-1", "CVE-9"),
		rec("GHSA-z", nil, "", "CVE-9"),
	}
	if got := mustCollapse(in); !reflect.DeepEqual(ids(got), []string{"GHSA-a", "GHSA-z"}) {
		t.Errorf("got %v", ids(got))
	}
}

// A same_as naming a record that is not in this answer joins nothing.
func TestCollapseSameAs_DanglingReferenceJoinsNothing(t *testing.T) {
	in := []vulnsource.Record{rec("A", []string{"MISSING"}, "")}
	if got := mustCollapse(in); len(got) != 1 || got[0].ID != "A" {
		t.Errorf("got %v", ids(got))
	}
}

func TestAddProvenanceMetadata_NoWallClockForLive(t *testing.T) {
	r := vulnsource.Record{Provenance: []vulnsource.Provenance{
		{Source: "osv.dev", Via: "live", RetrievedAt: "2026-10-25T06:00:00Z"},
		{Source: "osv.dev", Via: "mirror", RetrievedAt: "2026-10-25T04:00:00Z"},
	}}
	m := map[string]string{}
	addProvenanceMetadata(m, &r)
	want := map[string]string{"advisory_source": "osv.dev", "advisory_via": "live,mirror", "advisory_mirror_synced_at": "2026-10-25T04:00:00Z"}
	if !reflect.DeepEqual(m, want) {
		t.Errorf("meta = %v, want %v", m, want)
	}
	m = map[string]string{}
	addProvenanceMetadata(m, &vulnsource.Record{})
	if len(m) != 0 {
		t.Errorf("a record with no provenance gained metadata: %v", m)
	}
}

func mustCollapse(in []vulnsource.Record) []vulnsource.Record {
	out, _ := collapseSameAs(in)
	return out
}

func goRec(id string, sameAs []string, sev string, imports []vulnsource.Import, sym ...vulnsource.AffectedSymbols) vulnsource.Record {
	r := rec(id, sameAs, sev)
	r.Affected = []vulnsource.Affected{{
		Package:           vulnsource.Package{Name: "golang.org/x/net", Ecosystem: "Go"},
		EcosystemSpecific: vulnsource.EcosystemSpecific{Imports: imports},
	}}
	r.Symbols = sym
	return r
}

// The survivor is chosen for severity and gating, which in a Go answer is
// usually the GitHub advisory; the Go module advisory carries the import paths
// and symbols reachability reads. Collapsing kept only the survivor's, so with
// NOX Intelligence on, 219 of 362 decided Go verdicts across 8 real
// repositories fell back to undetermined. The absorbed record's scope and
// symbols must reach the survivor.
func TestCollapseSameAs_KeepsTheAbsorbedRecordsImportsAndSymbols(t *testing.T) {
	served := vulnsource.AffectedSymbols{AdvisoryID: "GO-2026-1", Ecosystem: "Go", Package: "golang.org/x/net",
		Method: "model-fix-diff", Status: vulnsource.SymbolStatusOK,
		Imports: []vulnsource.ImportSymbols{{Path: "golang.org/x/net/http2", Symbols: []string{"Server.ServeConn"}}}}
	in := []vulnsource.Record{
		goRec("GHSA-a", []string{"GO-2026-1"}, "HIGH", nil),
		goRec("GO-2026-1", []string{"GHSA-a"}, "", []vulnsource.Import{
			{Path: "golang.org/x/net/html", Symbols: []string{"Parse", "Tokenizer.Next"}},
		}, served),
	}
	for _, order := range [][]int{{0, 1}, {1, 0}} {
		got := mustCollapse([]vulnsource.Record{in[order[0]], in[order[1]]})
		if len(got) != 1 || got[0].ID != "GHSA-a" {
			t.Fatalf("order %v: got %v", order, ids(got))
		}
		r := got[0]
		if s := r.ListedSymbols("golang.org/x/net", "golang.org/x/net/html"); !reflect.DeepEqual(s, []string{"Parse", "Tokenizer.Next"}) {
			t.Errorf("order %v: the Go advisory's symbols = %v", order, s)
		}
		if s := r.ListedSymbols("golang.org/x/net", "golang.org/x/net/http2"); !reflect.DeepEqual(s, []string{"Server.ServeConn"}) {
			t.Errorf("order %v: the served nox_symbols = %v", order, s)
		}
	}
}

// An import path listed without symbols means the whole package is affected.
// Joining it with a list for the same path must keep "the whole package", not
// narrow it to the list.
func TestCollapseSameAs_WholePackageBeatsASymbolList(t *testing.T) {
	in := []vulnsource.Record{
		goRec("GHSA-a", []string{"GO-1"}, "HIGH", []vulnsource.Import{{Path: "golang.org/x/net/html", Symbols: []string{"Parse"}}}),
		goRec("GO-1", []string{"GHSA-a"}, "", []vulnsource.Import{{Path: "golang.org/x/net/html"}}),
	}
	got := mustCollapse(in)
	imps := got[0].Affected[0].EcosystemSpecific.Imports
	if len(imps) != 1 || imps[0].Path != "golang.org/x/net/html" || len(imps[0].Symbols) != 0 {
		t.Errorf("imports = %+v, want the whole package", imps)
	}
}
