package policy_test

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/policy"
)

func finding(rule string, sev findings.Severity, status findings.Status) findings.Finding {
	return findings.Finding{
		RuleID: rule, Severity: sev, Confidence: findings.ConfidenceHigh, Status: status,
		Location: findings.Location{FilePath: "app.go", StartLine: 1},
	}
}

func base(fs ...findings.Finding) policy.CIGate {
	return policy.CIGate{FindingsWritten: true, Findings: fs}
}

// THE one with a body count.
//
// A committed baseline that matches NOTHING is not the same as having no
// baseline, and treating them alike silently deletes the gate. nox v1.3.0
// changed the fingerprint algorithm, so every pre-1.3.0 digest stopped matching
// at once — the repository still looks triaged, the file is right there in git,
// and the gate exits 0 having evaluated nothing. Four repositories sat that way
// with the security check REQUIRED, one hiding two net-new critical/high.
//
// The symptom is a green check rather than a red one, which is why nobody
// noticed and why this test exists.
func TestACommittedBaselineThatMatchesNothingIsAnError(t *testing.T) {
	in := base(finding("SEC-001", findings.SeverityHigh, findings.StatusNew))
	in.BaselineExists = true

	r := policy.EvaluateCI(in)
	if r.Pass {
		t.Fatal("a committed baseline matching nothing passed the gate. That is fingerprint " +
			"drift reported as a clean repository, and the symptom is a green check.")
	}
	if !strings.Contains(strings.Join(r.Errors, " "), "fingerprint drift") {
		t.Errorf("the error does not name the cause: %v", r.Errors)
	}
	if !strings.Contains(strings.Join(r.Errors, " "), "baseline migrate") {
		t.Errorf("the error does not name the fix: %v", r.Errors)
	}
}

// An ABSENT baseline stays report-only. Adopting the gate must not break a
// build that was green, or the gate gets removed rather than adopted.
func TestNoBaselineIsReportOnly(t *testing.T) {
	r := policy.EvaluateCI(base(finding("SEC-001", findings.SeverityCritical, findings.StatusNew)))
	if !r.Pass {
		t.Error("an un-baselined repository was failed; adopting the gate would break a " +
			"build that was passing, and a gate that breaks builds on adoption gets removed")
	}
	if len(r.Warnings) == 0 {
		t.Error("report-only produced no warning, so the finding is invisible")
	}
}

// ...unless the repository opted in.
func TestStrictGatesAnUnbaselinedRepository(t *testing.T) {
	in := base(finding("SEC-001", findings.SeverityCritical, findings.StatusNew))
	in.Strict = true
	if policy.EvaluateCI(in).Pass {
		t.Error("strict mode passed a net-new critical finding")
	}
}

// A degraded scan is fatal whatever the baseline says. A required analyzer that
// did not run produces a findings file that is valid, healthy-looking, and
// missing exactly the findings nobody looked for.
func TestADegradedScanFailsIrrespectiveOfBaseline(t *testing.T) {
	in := base()
	in.Degradations = []policy.Degradation{{
		Kind: "plugin", Detail: "taint-analysis failed to install",
		Impact: "injection findings are absent, not clean",
	}}
	r := policy.EvaluateCI(in)
	if r.Pass {
		t.Fatal("a degraded scan passed. The findings file looks perfectly healthy: valid " +
			"JSON, real findings from the analyzers that DID run, and none from the one " +
			"that did not — indistinguishable from clean.")
	}
	if !strings.Contains(strings.Join(r.Errors, " "), "absent rather than clean") {
		t.Errorf("the error does not draw the distinction: %v", r.Errors)
	}
}

// Code-security families gate at ANY severity.
//
// gosec failed the lint job at any severity and was dropped on the premise that
// nox covered the same ground. Most of these rules are MEDIUM, honestly,
// because that is what one instance is worth — so under a critical/high gate
// they would never fail a build, and porting the rules would have restored the
// coverage on paper and none of the enforcement.
func TestCodeSecurityFamiliesGateAtAnySeverity(t *testing.T) {
	for _, rule := range []string{"HARDEN-001", "PERM-002", "CRYPTO-003", "MEMSAFE-004"} {
		t.Run(rule, func(t *testing.T) {
			in := base(finding(rule, findings.SeverityMedium, findings.StatusNew))
			in.Strict = true
			if policy.EvaluateCI(in).Pass {
				t.Errorf("a medium %s finding passed; this family gates at any severity", rule)
			}
		})
	}
}

// A suppressed finding is an explicit accept and does not gate — that is what
// makes the gate usable at all.
func TestAnAcceptedFindingDoesNotGate(t *testing.T) {
	in := base(
		finding("HARDEN-001", findings.SeverityMedium, findings.StatusBaselined),
		finding("SEC-001", findings.SeverityCritical, findings.StatusSuppressed),
	)
	in.BaselineExists = true
	r := policy.EvaluateCI(in)
	if !r.Pass {
		t.Errorf("an explicitly accepted finding gated the build: %v", r.Errors)
	}
	if r.Baselined != 1 {
		t.Errorf("baselined = %d, want 1", r.Baselined)
	}
}

// A missing findings.json is fatal where the repository gates and report-only
// where it does not — the same asymmetry as the baseline, for the same reason.
func TestNoFindingsFile(t *testing.T) {
	if policy.EvaluateCI(policy.CIGate{}).Pass != true {
		t.Error("an un-baselined repository with no findings file was failed")
	}
	if policy.EvaluateCI(policy.CIGate{BaselineExists: true}).Pass {
		t.Error("a gating repository with no findings file passed, having evaluated nothing")
	}
}

// The counts are reported whatever the decision, so a green run says what it
// evaluated rather than only that it passed.
func TestCountsAreReportedOnAPass(t *testing.T) {
	in := base(
		finding("SEC-001", findings.SeverityHigh, findings.StatusBaselined),
		finding("SEC-002", findings.SeverityLow, findings.StatusNew),
	)
	in.BaselineExists = true
	r := policy.EvaluateCI(in)
	if !r.Pass {
		t.Fatalf("unexpected failure: %v", r.Errors)
	}
	if r.Baselined != 1 {
		t.Errorf("baselined = %d, want 1", r.Baselined)
	}
	if r.NetNewHigh != 0 {
		t.Errorf("net-new high = %d, want 0", r.NetNewHigh)
	}
}

// An advisory degradation warns; it does not gate.
//
// The bash this replaces counted `.meta.degradations | length` and failed on
// any entry, on the stated premise that "repos that have not opted in produce
// no degradations and are unaffected". That premise is false: nox raises a
// plugin degradation listing installed plugins that are NOT in
// plugins.required — the opposite case — so any runner with an undeclared
// plugin failed the gate having asked for nothing.
//
// Reproduced on nox's own tree during the port: fifteen undeclared plugins,
// exit 1, no required analyzer involved. Filed as klarlabs-studio/.github#80,
// and fixed at the type in nox-core v0.3.1 — this asserts the FIELD, not the
// impact-text match it replaced.
func TestAnAdvisoryDegradationDoesNotGate(t *testing.T) {
	in := base()
	in.Degradations = []policy.Degradation{{
		Kind:     "plugin",
		Detail:   "15 installed plugin(s) are not listed in plugins.required and did not run",
		Impact:   "their findings are absent from this scan; add the ones you want",
		Advisory: true,
	}}
	r := policy.EvaluateCI(in)
	if !r.Pass {
		t.Errorf("an advisory degradation failed the build: %v. It reports capability the "+
			"repository deliberately did not enable; gating on it is a false red on the "+
			"opposite condition to the one this gate exists for.", r.Errors)
	}
	if len(r.Warnings) == 0 {
		t.Error("the advisory was silenced rather than reported; it is still worth seeing")
	}
}

// A blocking degradation still gates, so the distinction is not a way to
// silence the check.
func TestABlockingDegradationStillGates(t *testing.T) {
	in := base()
	in.Degradations = []policy.Degradation{{
		Kind:   "plugin",
		Detail: "required plugin nox/taint-analysis failed to install",
		Impact: "injection, SSRF and path-traversal findings are absent, not clean",
	}}
	if policy.EvaluateCI(in).Pass {
		t.Error("a required analyzer that did not run passed the gate")
	}
}

// Both at once: the advisory must not mask the blocking one.
func TestAnAdvisoryDoesNotMaskABlockingDegradation(t *testing.T) {
	in := base()
	in.Degradations = []policy.Degradation{
		{Kind: "plugin", Detail: "undeclared", Impact: "add the ones you want", Advisory: true},
		{Kind: "osv_lookup", Detail: "OSV unreachable", Impact: "cannot confirm the absence of known CVEs"},
	}
	r := policy.EvaluateCI(in)
	if r.Pass {
		t.Error("a blocking degradation was masked by an advisory one alongside it")
	}
	if len(r.Warnings) == 0 {
		t.Error("the advisory was dropped rather than reported")
	}
}

// The advisory flag survives from the analyzer that set it to the gate that
// reads it.
//
// It did not, at first. core/scan re-added each hook degradation through
// degradations.Add(kind, detail, impact) — three positional arguments that
// cannot carry a fourth field — so Advisory was dropped between the hook that
// set it and the artifact. Silently, and in the dangerous direction: a lost
// bool defaults to blocking, which is what the old behaviour was, so nothing
// looked wrong. It surfaced only because the gate started failing a scan it had
// just passed.
//
// Asserted here at the gate rather than at the collector, because the collector
// was not where it broke — the seam between them was.
func TestAdvisorySurvivesTheArtifactRoundTrip(t *testing.T) {
	in := base()
	in.Degradations = []policy.Degradation{{
		Kind:     "plugin",
		Detail:   "15 installed plugin(s) are not listed in plugins.required",
		Impact:   "their findings are absent from this scan; add the ones you want",
		Advisory: true,
	}}
	if !policy.EvaluateCI(in).Pass {
		t.Error("an advisory degradation gated the build; the flag did not reach the gate")
	}

	// And the same degradation without the flag still blocks, so the test above
	// is not passing because the gate stopped checking.
	in.Degradations[0].Advisory = false
	if policy.EvaluateCI(in).Pass {
		t.Error("clearing Advisory did not restore blocking; the gate is ignoring the field")
	}
}
