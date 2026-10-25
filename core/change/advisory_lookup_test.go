package change

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/report"
)

func hasCaveat(d Delta, sub string) bool {
	for _, c := range d.Caveats {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

// An offline scan reports no advisories because it did not look, not because
// there are none. Comparing it with an online scan listed every pre-existing
// advisory as new.
func TestAdvisoriesAreNotComparedWhenOneSideDidNotLookThemUp(t *testing.T) {
	adv := vuln("package-lock.json", "qs", "6.13.0", "GHSA-q", "", findings.SeverityMedium)
	other := plain("IAC-502", "deploy/k8s.yaml", 4, "literal password", findings.SeverityHigh)

	offline := st("previous run", other)
	offline.AdvisoryLookup = "the scan was offline"
	online := st("this run", adv, other)

	d := Compare(offline, online)
	if len(d.New) != 0 || len(d.Resolved) != 0 {
		t.Fatalf("advisories listed against a scan that never looked: new=%v resolved=%v", d.New, d.Resolved)
	}
	if !hasCaveat(d, "the previous scan did not look up advisories") {
		t.Errorf("caveat missing (previous side): %v", d.Caveats)
	}

	// The other direction: this run is the one that did not look.
	d = Compare(online, offline)
	if len(d.New) != 0 || len(d.Resolved) != 0 {
		t.Fatalf("reverse: advisories read as resolved: new=%v resolved=%v", d.New, d.Resolved)
	}
	if !hasCaveat(d, "this scan did not look up advisories") {
		t.Errorf("caveat missing (this side): %v", d.Caveats)
	}

	// Everything else is still compared.
	more := offline
	more.Findings = append(append([]findings.Finding{}, more.Findings...), plain("SEC-1", "a.go", 1, "m", findings.SeverityHigh))
	d = Compare(st("previous run", other), more)
	if len(d.New) != 1 || d.New[0].RuleID != "SEC-1" {
		t.Errorf("non-advisory findings must still compare, got %v", d.New)
	}
}

func TestAdvisoriesAreComparedWhenBothSidesLookedThemUp(t *testing.T) {
	adv := vuln("package-lock.json", "qs", "6.13.0", "GHSA-q", "", findings.SeverityMedium)
	d := Compare(st("previous run"), st("this run", adv))
	if len(d.New) != 1 {
		t.Fatalf("new = %v, want the advisory", d.New)
	}
	if hasCaveat(d, "advisories") {
		t.Errorf("unexpected advisory caveat: %v", d.Caveats)
	}
}

func TestFromReportRecordsWhyAdvisoriesWereNotLookedUp(t *testing.T) {
	cases := map[string]report.JSONReport{
		"offline":  {Meta: report.Meta{Offline: true}},
		"disabled": {Meta: report.Meta{AdvisoryLookup: report.AdvisoryLookupSkipped}},
		"failed":   {Meta: report.Meta{Degradations: []report.Degradation{{Kind: "osv_lookup", Detail: "timeout"}}}},
	}
	for name, rep := range cases {
		if got := FromReport(rep, nil, "x").AdvisoryLookup; got == "" {
			t.Errorf("%s: advisory lookup not marked as missing", name)
		}
	}
	// A report from before the field existed, written online, is trusted.
	if got := FromReport(report.JSONReport{}, nil, "x").AdvisoryLookup; got != "" {
		t.Errorf("legacy online report marked as not looked up: %q", got)
	}
}

// A lookup the source said was incomplete is not a clean one: an advisory
// absent from it may simply not have been fetched, so comparing it against a
// full scan would report every missing advisory as resolved.
func TestIncompleteLookupIsNotComparedAndReadsFromTheReport(t *testing.T) {
	rep := report.JSONReport{Meta: report.Meta{AdvisoryLookup: report.AdvisoryLookupIncomplete}}
	s := FromReport(rep, nil, "this run")
	if s.AdvisoryLookup != LookupIncomplete {
		t.Fatalf("AdvisoryLookup = %q, want %q", s.AdvisoryLookup, LookupIncomplete)
	}

	adv := vuln("package-lock.json", "qs", "6.13.0", "GHSA-q", "", findings.SeverityMedium)
	full := st("previous run", adv)
	d := Compare(full, s)
	if len(d.Resolved) != 0 {
		t.Errorf("an advisory missing from an incomplete lookup read as resolved: %v", d.Resolved)
	}
	if !hasCaveat(d, "only partly looked up advisories (" + LookupIncomplete + ")") {
		t.Errorf("caveat missing: %v", d.Caveats)
	}
}
