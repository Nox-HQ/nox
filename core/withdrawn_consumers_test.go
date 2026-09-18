package core

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox/core/baseline"
	"github.com/nox-hq/nox/core/rules"
	"github.com/nox-hq/nox/core/vex"
)

// RetiredRule names three places an operator writes a rule ID down: baselines,
// VEX statements and `nox:ignore` comments. A withdrawn rule breaks all three,
// and each fails more quietly than the last -- a waiver at least earns an
// unused-waiver degradation, while a baseline entry and a VEX statement for a
// withdrawn rule produce nothing whatsoever.
//
// These cover the two silent ones. The waiver path is in
// withdrawn_waiver_test.go.

func withdrawnID(t *testing.T) (string, rules.WithdrawnRule) {
	t.Helper()
	ids := rules.WithdrawnIDs()
	if len(ids) == 0 {
		t.Fatal("no withdrawn rules registered; these tests would pass vacuously")
	}
	w, _ := rules.Withdrawn(ids[0])
	return ids[0], w
}

func TestABaselineEntryForAWithdrawnRuleIsExplained(t *testing.T) {
	t.Parallel()

	id, w := withdrawnID(t)
	bl := &baseline.Baseline{Entries: []baseline.Entry{
		{Fingerprint: "a", RuleID: id, FilePath: "x.py"},
		{Fingerprint: "b", RuleID: id, FilePath: "y.py"},
		{Fingerprint: "c", RuleID: "SEC-001", FilePath: "z.py"},
	}}
	deg := &degrade.Degradations{}
	reportWithdrawnBaselineEntries(bl, ".nox/baseline.json", deg)

	all := deg.Items()
	if len(all) != 1 {
		t.Fatalf("expected one degradation per withdrawn rule, got %d: %+v", len(all), all)
	}
	msg := fmt.Sprintf("%+v", all[0])
	for _, want := range []string{id, w.Version, "2 entries", "can be deleted"} {
		if !strings.Contains(msg, want) {
			t.Errorf("baseline explanation omits %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "SEC-001") {
		t.Errorf("a live rule's entry was reported as withdrawn:\n%s", msg)
	}
}

func TestAVEXStatementForAWithdrawnRuleIsExplained(t *testing.T) {
	t.Parallel()

	id, w := withdrawnID(t)
	doc := &vex.Document{Statements: []vex.Statement{
		{VulnerabilityID: id, Status: vex.StatusNotAffected},
		{VulnerabilityID: "SEC-001", Status: vex.StatusNotAffected},
	}}
	deg := &degrade.Degradations{}
	reportWithdrawnVEXStatements(doc, "vex.json", deg)

	all := deg.Items()
	if len(all) != 1 {
		t.Fatalf("expected one degradation, got %d: %+v", len(all), all)
	}
	msg := fmt.Sprintf("%+v", all[0])
	for _, want := range []string{id, w.Version, "can be deleted"} {
		if !strings.Contains(msg, want) {
			t.Errorf("VEX explanation omits %q:\n%s", want, msg)
		}
	}
}

func TestNothingIsReportedWhenNoRuleWasWithdrawn(t *testing.T) {
	t.Parallel()

	deg := &degrade.Degradations{}
	reportWithdrawnBaselineEntries(&baseline.Baseline{Entries: []baseline.Entry{
		{RuleID: "SEC-001"}, {RuleID: "SEC-454"}, // SEC-454 is RETIRED, not withdrawn
	}}, "b.json", deg)
	reportWithdrawnVEXStatements(&vex.Document{Statements: []vex.Statement{
		{VulnerabilityID: "IAC-013"},
	}}, "v.json", deg)

	if n := len(deg.Items()); n != 0 {
		t.Errorf("live and merely-retired rules produced %d withdrawal notice(s): %+v", n, deg.Items())
	}
}
