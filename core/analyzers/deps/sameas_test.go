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
	got := collapseSameAs(in)
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
		got := collapseSameAs([]vulnsource.Record{in[order[0]], in[order[1]]})
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
	got := collapseSameAs(in)
	if !reflect.DeepEqual(ids(got), []string{"A", "OTHER"}) {
		t.Errorf("got %v, want [A OTHER]", ids(got))
	}
}

// Without nox_same_as nothing is joined, even for records that list each other
// as aliases: OSV.dev and an older service behave exactly as before.
func TestCollapseSameAs_AliasesAloneJoinNothing(t *testing.T) {
	in := []vulnsource.Record{rec("GO-1", nil, "", "GHSA-a"), rec("GHSA-a", nil, "", "GO-1")}
	if got := collapseSameAs(in); len(got) != 2 {
		t.Errorf("got %v", ids(got))
	}
}

// A same_as naming a record that is not in this answer joins nothing.
func TestCollapseSameAs_DanglingReferenceJoinsNothing(t *testing.T) {
	in := []vulnsource.Record{rec("A", []string{"MISSING"}, "")}
	if got := collapseSameAs(in); len(got) != 1 || got[0].ID != "A" {
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
