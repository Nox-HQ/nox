package change

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/infra"
	"github.com/nox-hq/nox/core/report"
)

func infraState(label string, recorded bool, rs ...infra.Resource) State {
	s := State{Label: label, LeadsRecorded: true, InfrastructureRecorded: recorded}
	if len(rs) > 0 {
		inv := &infra.Inventory{Resources: rs}
		inv.Normalize()
		s.Infrastructure = inv
	}
	return s
}

func bucket(block string) infra.Resource {
	return infra.Resource{Kind: "aws_s3_bucket", Name: "uploads", File: "deploy/tf/main.tf", Class: infra.ClassBucket,
		Properties: map[string]string{"public_access_block": block}}
}

// The scenario that motivated the section: the bucket's block was all true and
// is now false. The finding alone says "a bucket is public"; it cannot say the
// earlier assumption no longer holds.
func TestWeakenedPropertyIsNamed(t *testing.T) {
	prev := infraState("main", true, bucket("all true"))
	cur := infraState("HEAD", true, bucket("all false"))
	cur.Findings = []findings.Finding{plain("IAC-504", "deploy/tf/main.tf", 5, "public access block disabled", findings.SeverityCritical)}
	d := Compare(prev, cur)
	if len(d.New) != 1 {
		t.Fatalf("the findings list must stay as it is: %+v", d.New)
	}
	if len(d.Infrastructure) != 1 || d.Infrastructure[0].Direction != infra.Weaker {
		t.Fatalf("want one weakened property, got %+v", d.Infrastructure)
	}
	text := Text(d, 0)
	want := "aws_s3_bucket.uploads (deploy/tf/main.tf): public access block \u2014 was all true, now all false"
	if !strings.Contains(text, "Infrastructure assumptions weakened (1):") || !strings.Contains(text, want) {
		t.Errorf("text missing the section or the line %q:\n%s", want, text)
	}
	if d.Empty() {
		t.Error("a delta with an infrastructure change is not empty")
	}
	if d.Regressions() != 1 {
		t.Errorf("infrastructure changes are hints and must not move the regression count: %d", d.Regressions())
	}
}

func TestStrengthenedPropertyIsNamedSeparately(t *testing.T) {
	d := Compare(infraState("a", true, bucket("all false")), infraState("b", true, bucket("all true")))
	text := Text(d, 0)
	if !strings.Contains(text, "Infrastructure assumptions strengthened (1):") || strings.Contains(text, "weakened") {
		t.Errorf("a hardened bucket must be listed as strengthened only:\n%s", text)
	}
}

func TestPureMoveIsSilent(t *testing.T) {
	a, b := bucket("all true"), bucket("all true")
	a.Line, b.Line = 1, 80
	d := Compare(infraState("a", true, a), infraState("b", true, b))
	if len(d.Infrastructure) != 0 || !d.Empty() {
		t.Errorf("a move produced %+v", d.Infrastructure)
	}
	if strings.Contains(Text(d, 0), "Infrastructure") {
		t.Error("an empty infrastructure section must not be rendered")
	}
}

// An earlier findings.json written before the inventory existed cannot be
// compared; saying nothing would read as "nothing weakened".
func TestPreInventoryPreviousStateGetsACaveatNotAFalseAllClear(t *testing.T) {
	prev := infraState("old findings.json", false)
	cur := infraState("this run", true, bucket("all false"))
	d := Compare(prev, cur)
	if len(d.Infrastructure) != 0 {
		t.Fatalf("nothing can be compared: %+v", d.Infrastructure)
	}
	found := false
	for _, c := range d.Caveats {
		if strings.Contains(c, "Infrastructure assumptions were not compared") && strings.Contains(c, "1 resources") {
			found = true
		}
	}
	if !found {
		t.Errorf("want a caveat naming the gap, got %v", d.Caveats)
	}
}

func TestNoCaveatWhenThereIsNoInfrastructureToCompare(t *testing.T) {
	d := Compare(infraState("old", false), infraState("new", true))
	if len(d.Caveats) != 0 {
		t.Errorf("a tree with no IaC needs no caveat: %v", d.Caveats)
	}
}

// A previous tree that recorded no resources and a current one that has them is
// a comparison that can be made: nothing was weakened, resources were added.
func TestRecordedEmptyPreviousIsComparable(t *testing.T) {
	d := Compare(infraState("a", true), infraState("b", true, bucket("all false")))
	if len(d.Infrastructure) != 0 || len(d.Caveats) != 0 {
		t.Errorf("new resources are not weakened properties: %+v %v", d.Infrastructure, d.Caveats)
	}
}

// findings.json round trip: the state `--previous` loads sees the same
// inventory the scan wrote, and one written without the key is "not recorded".
func TestFromReportRecordsOnlyWhatTheReportCarries(t *testing.T) {
	inv := &infra.Inventory{Resources: []infra.Resource{bucket("all true")}}
	inv.Normalize()
	raw, err := json.Marshal(report.JSONReport{Infrastructure: inv})
	if err != nil {
		t.Fatal(err)
	}
	var back report.JSONReport
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if s := FromReport(back, nil, "x"); !s.InfrastructureRecorded || s.Infrastructure.Resources[0].Properties["public_access_block"] != "all true" {
		t.Errorf("round trip lost the inventory: %+v", s.Infrastructure)
	}
	if s := FromReport(report.JSONReport{}, nil, "x"); s.InfrastructureRecorded {
		t.Error("a report without the key must not read as an empty inventory")
	}
}

func TestInfrastructureLimitsSummarise(t *testing.T) {
	var rs []infra.Resource
	var rs2 []infra.Resource
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		r := infra.Resource{Kind: "Deployment", Name: n, File: "d.yaml", Properties: map[string]string{"privileged": "false"}}
		rs = append(rs, r)
		r.Properties = map[string]string{"privileged": "true"}
		rs2 = append(rs2, r)
	}
	d := Compare(infraState("a", true, rs...), infraState("b", true, rs2...))
	text := Text(d, DefaultLimit)
	if !strings.Contains(text, "Infrastructure assumptions weakened (7):") || !strings.Contains(text, "...and 2 more") {
		t.Errorf("the section must honour the shared line limit:\n%s", text)
	}
}
