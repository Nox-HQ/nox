package advisory

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// adv builds a VULN-001 finding the way the dependency analyzer does.
func adv(id, pkg, from, fixed string, sev findings.Severity, outcome, reached string) findings.Finding {
	meta := map[string]string{
		"vuln_id":               id,
		"package":               pkg,
		"version":               from,
		"ecosystem":             "npm",
		"applicability":         outcome,
		"applicability_reached": reached,
	}
	if outcome == "undetermined" {
		meta["applicability_stopped_at"] = "symbol_used"
		meta["applicability_because"] = "unsupported"
	}
	if fixed != "" {
		meta["fixed_in"] = fixed
	}
	return findings.Finding{
		RuleID:   "VULN-001",
		Severity: sev,
		Location: findings.Location{FilePath: "package-lock.json", StartLine: 1},
		Metadata: meta,
	}
}

func mustPolicy(t *testing.T, s Settings) Policy {
	t.Helper()
	p, err := s.Resolve()
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return p
}

func only(t *testing.T, r Result) Decision {
	t.Helper()
	if len(r.Decisions) != 1 {
		t.Fatalf("want 1 decision, got %d: %+v", len(r.Decisions), r.Decisions)
	}
	return r.Decisions[0]
}

// The default must be the least autonomous level. An operator who installs the
// workflow and writes no policy must not get pull requests or merges.
func TestDefaultPolicyIsReport(t *testing.T) {
	p := mustPolicy(t, Settings{})
	if p.Level != Report {
		t.Fatalf("default level = %q, want report", p.Level)
	}
	f := adv("GHSA-1", "left-pad", "1.0.0", "1.0.1", findings.SeverityCritical, "impacting", "call_reachable")
	r := Evaluate(Input{Findings: []findings.Finding{f}, HavePrevious: true, Policy: p})
	d := only(t, r)
	if d.Action != ActionReport {
		t.Fatalf("action = %q, want report even for a reachable critical with a safe fix", d.Action)
	}
	if r.Action != ActionReport || r.AutoMerge || len(r.Prepare) != 0 {
		t.Fatalf("result must be report-only: %+v", r)
	}
}

func TestSettingsRejectNonsense(t *testing.T) {
	bad := []Settings{
		{Policy: "yolo"},
		{Prepare: Gate{MinSeverity: "urgent"}},
		{Prepare: Gate{MinRelevance: "reachable"}},
		// not_impacting is the one relevance an action may never be taken on.
		{Prepare: Gate{MinRelevance: "not_impacting"}},
		{Remediate: RemediateGate{MaxBump: "major"}},
	}
	for _, s := range bad {
		if _, err := s.Resolve(); err == nil {
			t.Errorf("Resolve(%+v) accepted an invalid setting", s)
		}
	}
}

// Same findings and baseline, same decision, in the same order.
func TestEvaluateIsDeterministic(t *testing.T) {
	ff := []findings.Finding{
		adv("GHSA-b", "b", "1.0.0", "1.0.1", findings.SeverityMedium, "undetermined", "affected_version"),
		adv("GHSA-a", "a", "1.0.0", "1.0.1", findings.SeverityHigh, "undetermined", "affected_version"),
		adv("GHSA-c", "c", "1.0.0", "1.0.1", findings.SeverityHigh, "undetermined", "affected_version"),
	}
	p := mustPolicy(t, Settings{Policy: "prepare"})
	first := Evaluate(Input{Findings: ff, HavePrevious: true, Policy: p})
	for i := 0; i < 20; i++ {
		rev := []findings.Finding{ff[2], ff[0], ff[1]}
		again := Evaluate(Input{Findings: rev, HavePrevious: true, Policy: p})
		if len(again.Decisions) != len(first.Decisions) {
			t.Fatal("decision count changed")
		}
		for j := range first.Decisions {
			if first.Decisions[j].Advisory != again.Decisions[j].Advisory ||
				first.Decisions[j].Action != again.Decisions[j].Action ||
				first.Decisions[j].Reason != again.Decisions[j].Reason {
				t.Fatalf("decision %d differs between runs: %+v vs %+v", j, first.Decisions[j], again.Decisions[j])
			}
		}
	}
	if first.Decisions[0].Advisory != "GHSA-a" {
		t.Fatalf("not ordered by severity then package: %s first", first.Decisions[0].Advisory)
	}
}

// Undetermined is "we could not tell", not "not affected". It must never be
// folded into the refuted case, and the reason must say so.
func TestUndeterminedIsNotNotAffected(t *testing.T) {
	f := adv("GHSA-u", "express", "4.0.0", "4.0.1", findings.SeverityHigh, "undetermined", "affected_version")
	p := mustPolicy(t, Settings{Policy: "prepare"})
	d := only(t, Evaluate(Input{Findings: []findings.Finding{f}, HavePrevious: true, Policy: p}))
	if d.Relevance != RelUndetermined {
		t.Fatalf("relevance = %q, want undetermined", d.Relevance)
	}
	if d.Action != ActionPrepare {
		t.Fatalf("an undetermined high with a fix must be prepared under the default gate, got %q", d.Action)
	}
	if !strings.Contains(d.Reason, "could not") || strings.Contains(strings.ToLower(d.Reason), "not affected") {
		t.Fatalf("reason must say the question was not answered, got %q", d.Reason)
	}
}

// A refuted advisory is shown, with the reason, and never acted on.
func TestNotImpactingIsReportedNeverActed(t *testing.T) {
	f := adv("GHSA-n", "x", "1.0.0", "1.0.1", findings.SeverityCritical, "not_impacting", "affected_version")
	p := mustPolicy(t, Settings{Policy: "remediate"})
	r := Evaluate(Input{Findings: []findings.Finding{f}, HavePrevious: true, Policy: p})
	d := only(t, r)
	if d.Relevance != RelNotImpacting || d.Action != ActionReport {
		t.Fatalf("got relevance=%q action=%q", d.Relevance, d.Action)
	}
	if len(r.Prepare) != 0 || r.AutoMerge {
		t.Fatalf("a refuted advisory must produce no PR and no merge: %+v", r)
	}
}

func TestRelevanceLadderFromApplicability(t *testing.T) {
	cases := []struct {
		outcome, reached string
		want             Relevance
	}{
		{"undetermined", "affected_version", RelUndetermined},
		{"", "", RelUndetermined},
		// Go: linked but no call path established. Still more than undetermined.
		{"undetermined", "symbol_used", RelSymbolUsed},
		{"impacting", "symbol_used", RelSymbolUsed},
		{"impacting", "call_reachable", RelCallReachable},
		{"impacting", "attacker_reachable", RelCallReachable},
		{"not_impacting", "affected_version", RelNotImpacting},
	}
	for _, c := range cases {
		f := adv("GHSA-r", "p", "1.0.0", "1.0.1", findings.SeverityHigh, c.outcome, c.reached)
		if got := relevanceOf(&f); got != c.want {
			t.Errorf("(%q,%q) = %q, want %q", c.outcome, c.reached, got, c.want)
		}
	}
}

func TestThresholdsGatePrepare(t *testing.T) {
	p := mustPolicy(t, Settings{
		Policy:  "prepare",
		Prepare: Gate{MinSeverity: "high", MinRelevance: "symbol_used"},
	})
	cases := []struct {
		name    string
		sev     findings.Severity
		outcome string
		reached string
		want    Action
		reason  string
	}{
		{"meets both", findings.SeverityHigh, "impacting", "symbol_used", ActionPrepare, ""},
		{"too low severity", findings.SeverityMedium, "impacting", "call_reachable", ActionReport, "severity"},
		{"too little relevance", findings.SeverityCritical, "undetermined", "affected_version", ActionReport, "relevance"},
	}
	for _, c := range cases {
		f := adv("GHSA-t", "p", "1.0.0", "1.0.1", c.sev, c.outcome, c.reached)
		d := only(t, Evaluate(Input{Findings: []findings.Finding{f}, HavePrevious: true, Policy: p}))
		if d.Action != c.want {
			t.Errorf("%s: action = %q, want %q (%s)", c.name, d.Action, c.want, d.Reason)
		}
		if c.reason != "" && !strings.Contains(d.Reason, c.reason) {
			t.Errorf("%s: reason %q should mention %q", c.name, d.Reason, c.reason)
		}
	}
}

// Nothing to prepare when no fixed version exists; saying "prepare" there would
// promise a pull request that cannot be built.
func TestNoFixMeansReport(t *testing.T) {
	f := adv("GHSA-nofix", "p", "1.0.0", "", findings.SeverityCritical, "impacting", "call_reachable")
	p := mustPolicy(t, Settings{Policy: "remediate"})
	r := Evaluate(Input{Findings: []findings.Finding{f}, HavePrevious: true, Policy: p})
	d := only(t, r)
	if d.Action != ActionReport || !strings.Contains(d.Reason, "no fixed version") {
		t.Fatalf("got %q / %q", d.Action, d.Reason)
	}
	if len(r.Prepare) != 0 {
		t.Fatal("nothing to prepare")
	}
}

// A major bump is never prepared by this flow, same as nox fix's default.
func TestMajorBumpIsReportedForAPerson(t *testing.T) {
	f := adv("GHSA-major", "p", "1.9.0", "2.0.0", findings.SeverityCritical, "impacting", "call_reachable")
	p := mustPolicy(t, Settings{Policy: "remediate"})
	d := only(t, Evaluate(Input{Findings: []findings.Finding{f}, HavePrevious: true, Policy: p}))
	if d.Action != ActionReport || !strings.Contains(d.Reason, "major") {
		t.Fatalf("got %q / %q", d.Action, d.Reason)
	}
}

func TestRemediateRequiresSafeBumpAndGate(t *testing.T) {
	p := mustPolicy(t, Settings{Policy: "remediate"}) // defaults: high, symbol_used, minor
	good := adv("GHSA-ok", "a", "1.2.3", "1.2.4", findings.SeverityHigh, "impacting", "symbol_used")
	r := Evaluate(Input{Findings: []findings.Finding{good}, HavePrevious: true, Policy: p})
	d := only(t, r)
	if d.Action != ActionRemediate || !r.AutoMerge || r.Action != ActionRemediate {
		t.Fatalf("a high, used, patch bump should remediate: %+v", r)
	}

	// Undetermined relevance never auto-merges under the default gate, even
	// though it is prepared: nobody established the code is used.
	und := adv("GHSA-und", "b", "1.2.3", "1.2.4", findings.SeverityCritical, "undetermined", "affected_version")
	r = Evaluate(Input{Findings: []findings.Finding{und}, HavePrevious: true, Policy: p})
	d = only(t, r)
	if d.Action != ActionPrepare || r.AutoMerge {
		t.Fatalf("undetermined must prepare but not merge: action=%q merge=%v", d.Action, r.AutoMerge)
	}

	// max_bump: patch refuses a minor.
	p2 := mustPolicy(t, Settings{Policy: "remediate", Remediate: RemediateGate{MaxBump: "patch"}})
	minor := adv("GHSA-minor", "c", "1.2.3", "1.3.0", findings.SeverityHigh, "impacting", "symbol_used")
	r = Evaluate(Input{Findings: []findings.Finding{minor}, HavePrevious: true, Policy: p2})
	d = only(t, r)
	if d.Action != ActionPrepare || r.AutoMerge || !strings.Contains(d.Reason, "minor") {
		t.Fatalf("minor under max_bump=patch: %q merge=%v %q", d.Action, r.AutoMerge, d.Reason)
	}
}

// One pull request carries every prepared upgrade. Auto-merging it because one
// of them is safe would merge the others unreviewed.
func TestAutoMergeNeedsEveryPreparedAdvisorySafe(t *testing.T) {
	p := mustPolicy(t, Settings{Policy: "remediate"})
	safe := adv("GHSA-s", "a", "1.0.0", "1.0.1", findings.SeverityHigh, "impacting", "symbol_used")
	unsure := adv("GHSA-u", "b", "1.0.0", "1.0.1", findings.SeverityHigh, "undetermined", "affected_version")
	r := Evaluate(Input{Findings: []findings.Finding{safe, unsure}, HavePrevious: true, Policy: p})
	if r.AutoMerge {
		t.Fatal("must not auto-merge a PR that includes a prepare-only advisory")
	}
	if r.Action != ActionRemediate {
		t.Fatalf("the strongest decision is still reported: %q", r.Action)
	}
	if len(r.Prepare) != 2 {
		t.Fatalf("both belong in the PR: %v", r.Prepare)
	}
}

// Two advisories on one package move to the highest fix, and the bump that is
// judged is that move, not each advisory's own fixed_in.
func TestBumpJudgedOnThePackageMove(t *testing.T) {
	p := mustPolicy(t, Settings{Policy: "remediate"})
	a := adv("GHSA-1", "lib", "1.2.0", "1.2.1", findings.SeverityHigh, "impacting", "symbol_used")
	b := adv("GHSA-2", "lib", "1.2.0", "1.4.0", findings.SeverityHigh, "impacting", "symbol_used")
	p2 := mustPolicy(t, Settings{Policy: "remediate", Remediate: RemediateGate{MaxBump: "patch"}})
	r := Evaluate(Input{Findings: []findings.Finding{a, b}, HavePrevious: true, Policy: p2})
	if r.AutoMerge {
		t.Fatal("the package moves to 1.4.0, a minor bump; max_bump=patch must refuse")
	}
	r = Evaluate(Input{Findings: []findings.Finding{a, b}, HavePrevious: true, Policy: p})
	if !r.AutoMerge {
		t.Fatalf("minor is allowed by default: %+v", r.Decisions)
	}
}

// Newness: waived and previously seen advisories are not acted on again.
func TestNovelty(t *testing.T) {
	p := mustPolicy(t, Settings{Policy: "remediate"})
	seen := adv("GHSA-old", "a", "1.0.0", "1.0.1", findings.SeverityCritical, "impacting", "call_reachable")
	fresh := adv("GHSA-new", "b", "1.0.0", "1.0.1", findings.SeverityCritical, "impacting", "call_reachable")
	waived := adv("GHSA-waived", "c", "1.0.0", "1.0.1", findings.SeverityCritical, "impacting", "call_reachable")
	waived.Status = findings.StatusBaselined
	vex := adv("GHSA-vex", "d", "1.0.0", "1.0.1", findings.SeverityCritical, "impacting", "call_reachable")
	vex.Status = findings.StatusVEXNotAffected

	r := Evaluate(Input{
		Findings:     []findings.Finding{seen, fresh, waived, vex},
		Previous:     []findings.Finding{seen},
		HavePrevious: true,
		Policy:       p,
	})
	got := map[string]Decision{}
	for _, d := range r.Decisions {
		got[d.Advisory] = d
	}
	if got["GHSA-new"].Novelty != NoveltyNew || got["GHSA-new"].Action != ActionRemediate {
		t.Errorf("new: %+v", got["GHSA-new"])
	}
	if got["GHSA-old"].Novelty != NoveltyKnown || got["GHSA-old"].Action != ActionNone {
		t.Errorf("known: %+v", got["GHSA-old"])
	}
	for _, id := range []string{"GHSA-waived", "GHSA-vex"} {
		if got[id].Novelty != NoveltyWaived || got[id].Action != ActionNone {
			t.Errorf("%s: %+v", id, got[id])
		}
	}
	if len(r.Prepare) != 1 {
		t.Fatalf("only the new advisory is prepared: %v", r.Prepare)
	}
}

// A package upgraded but still hit by the same advisory is not newly disclosed.
// A GHSA reported last week and returned as its CVE alias today is not either.
func TestKnownByAliasAndAcrossVersions(t *testing.T) {
	p := mustPolicy(t, Settings{Policy: "prepare"})
	prev := adv("GHSA-x", "lib", "1.0.0", "1.0.1", findings.SeverityHigh, "undetermined", "affected_version")
	prev.Metadata["aliases"] = "CVE-2026-0001"
	nowVersion := adv("GHSA-x", "lib", "1.0.5", "1.0.6", findings.SeverityHigh, "undetermined", "affected_version")
	nowAlias := adv("CVE-2026-0001", "lib", "1.0.0", "1.0.1", findings.SeverityHigh, "undetermined", "affected_version")
	for _, f := range []findings.Finding{nowVersion, nowAlias} {
		d := only(t, Evaluate(Input{Findings: []findings.Finding{f}, Previous: []findings.Finding{prev}, HavePrevious: true, Policy: p}))
		if d.Novelty != NoveltyKnown {
			t.Errorf("%s should be known: %+v", f.Metadata["vuln_id"], d)
		}
	}
	// Same id, different package: genuinely new.
	other := adv("GHSA-x", "other", "1.0.0", "1.0.1", findings.SeverityHigh, "undetermined", "affected_version")
	d := only(t, Evaluate(Input{Findings: []findings.Finding{other}, Previous: []findings.Finding{prev}, HavePrevious: true, Policy: p}))
	if d.Novelty != NoveltyNew {
		t.Errorf("different package must be new: %+v", d)
	}
}

// With nothing to compare against, "new" cannot be established. Everything is
// shown; nothing is acted on. Acting would open a pull request for every
// advisory in the repository on the first scheduled run.
func TestNoPreviousRunCapsAtReport(t *testing.T) {
	p := mustPolicy(t, Settings{Policy: "remediate"})
	f := adv("GHSA-1", "a", "1.0.0", "1.0.1", findings.SeverityCritical, "impacting", "call_reachable")
	r := Evaluate(Input{Findings: []findings.Finding{f}, HavePrevious: false, Policy: p})
	d := only(t, r)
	if d.Novelty != NoveltyUnestablished || d.Action != ActionReport {
		t.Fatalf("got %+v", d)
	}
	if r.AutoMerge || len(r.Prepare) != 0 || r.PreviousRun {
		t.Fatalf("no autonomous action without a previous run: %+v", r)
	}
	if !strings.Contains(d.Reason, "o previous run") {
		t.Fatalf("reason: %q", d.Reason)
	}
}

// A scan that could not finish looking cannot drive a merge, and must not
// read as a quiet week.
func TestIncompleteScanCapsAtReportAndSaysSo(t *testing.T) {
	p := mustPolicy(t, Settings{Policy: "remediate"})
	f := adv("GHSA-1", "a", "1.0.0", "1.0.1", findings.SeverityCritical, "impacting", "call_reachable")
	r := Evaluate(Input{Findings: []findings.Finding{f}, HavePrevious: true, Policy: p, Incomplete: "osv_lookup: OSV unreachable"})
	if r.Incomplete == "" || r.AutoMerge || len(r.Prepare) != 0 || r.Action != ActionReport {
		t.Fatalf("%+v", r)
	}
}

// Other rules are not advisories; this flow ignores them rather than guessing.
func TestNonAdvisoryFindingsIgnored(t *testing.T) {
	sec := findings.Finding{RuleID: "SEC-001", Severity: findings.SeverityCritical}
	r := Evaluate(Input{Findings: []findings.Finding{sec}, HavePrevious: true, Policy: mustPolicy(t, Settings{Policy: "remediate"})})
	if len(r.Decisions) != 0 || r.Action != ActionNone {
		t.Fatalf("%+v", r)
	}
}

// Theoretical (undisclosed) candidates are demoted to info by the analyzer and
// are not advisories anyone can upgrade away.
func TestTheoreticalIsReportOnly(t *testing.T) {
	f := adv("NOX-CAND-1", "a", "1.0.0", "1.0.1", findings.SeverityInfo, "undetermined", "affected_version")
	f.Metadata["theoretical"] = "true"
	f.Metadata["vuln_status"] = "CANDIDATE"
	r := Evaluate(Input{Findings: []findings.Finding{f}, HavePrevious: true, Policy: mustPolicy(t, Settings{Policy: "prepare", Prepare: Gate{MinSeverity: "low"}})})
	d := only(t, r)
	if d.Action != ActionReport {
		t.Fatalf("%+v", d)
	}
}
