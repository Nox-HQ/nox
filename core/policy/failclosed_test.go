package policy

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// This file pins the policy gate's FAIL-CLOSED contract.
//
// The dangerous failure for a security tool is not a false positive, it is the
// FALSE ALL-CLEAR: a gate reporting success when it could not actually
// evaluate. Every assertion here answers the same question — "when the gate
// cannot classify something, does it refuse to pass?" — and every one is
// written as a loop over the whole input space rather than as hand-picked
// cases, so a future edit cannot quietly widen the gate by one value and still
// see green.

// failClosedUndefinedSeverities are the strings an operator or a config file
// realistically produces that are NOT severities. The comparison is
// case-sensitive and lowercase-only, so every one of these is undefined.
var failClosedUndefinedSeverities = []findings.Severity{
	"",          // unset / zero value
	"Critical",  // capitalized
	"CRITICAL",  // shouted
	"critical ", // trailing space from YAML
	"criticl",   // typo
	"error",     // wrong vocabulary (SARIF level)
	"blocker",   // wrong vocabulary (SonarQube)
	"none",      // sounds like "off", means nothing here
	"warning",   // wrong vocabulary
	"0",         // numeric rank leaked from somewhere
}

// failClosedFinding builds a new (active, un-baselined) finding of a severity.
func failClosedFinding(sev findings.Severity) findings.Finding {
	return findings.Finding{
		RuleID:   "NOX-FAILCLOSED-001",
		Severity: sev,
		Status:   findings.StatusNew,
		Location: findings.Location{FilePath: "app/main.go", StartLine: 7},
	}
}

// TestFailClosed_MeetsThresholdRejectsEveryUndefinedSeverity walks the ENTIRE
// cross product of {defined severities} ∪ {undefined strings} on both sides of
// the comparison.
//
// meetsThreshold is the single predicate every gate decision routes through. If
// it ever answered true for a severity it does not recognise, an unrecognised
// value would inherit whatever ordering position the bug gave it — the exact
// shape of the risk-class bug where the empty string mapped to "passive" (0)
// and an unclassified plugin sailed past a passive ceiling. The rule is
// absolute: unknown on EITHER side is never "at or above".
func TestFailClosed_MeetsThresholdRejectsEveryUndefinedSeverity(t *testing.T) {
	t.Parallel()

	all := append(append([]findings.Severity{}, findings.SeverityOrder...), failClosedUndefinedSeverities...)

	for _, sev := range all {
		for _, threshold := range all {
			defined := sev.IsValid() && threshold.IsValid()
			want := defined && findings.SeverityRank(sev) <= findings.SeverityRank(threshold)

			if got := meetsThreshold(sev, threshold); got != want {
				t.Errorf("meetsThreshold(%q, %q) = %v, want %v (defined=%v)",
					sev, threshold, got, want, defined)
			}
		}
	}
}

// TestFailClosed_SeverityRankOKFlagsUndefinedLevels pins the helper the gate
// leans on. The rank of an unknown severity is deliberately NOT a sentinel that
// happens to sort safely — callers must consult the ok flag, so this asserts
// the flag itself rather than trusting the number.
func TestFailClosed_SeverityRankOKFlagsUndefinedLevels(t *testing.T) {
	t.Parallel()

	for i, sev := range findings.SeverityOrder {
		rank, ok := severityRankOK(sev)
		if !ok {
			t.Errorf("severityRankOK(%q) reported the level as undefined", sev)
		}
		if rank != i {
			t.Errorf("severityRankOK(%q) rank = %d, want %d", sev, rank, i)
		}
	}

	for _, sev := range failClosedUndefinedSeverities {
		if _, ok := severityRankOK(sev); ok {
			t.Errorf("severityRankOK(%q) reported an undefined severity as defined", sev)
		}
	}
}

// TestFailClosed_ValidateRejectsEveryUndefinedThreshold sweeps every undefined
// string through every gate keyword.
//
// A typo'd threshold does not weaken the gate, it DISABLES it: meetsThreshold
// returns false for a value it does not know, so nothing is ever gated and a
// scan full of criticals exits 0. That failure looks configured, which is worse
// than having no policy at all. Validation is the only thing standing between a
// capitalized "High" and a permanently green CI.
func TestFailClosed_ValidateRejectsEveryUndefinedThreshold(t *testing.T) {
	t.Parallel()

	for _, sev := range failClosedUndefinedSeverities {
		if sev == "" {
			// Empty is the legitimate "unset" for fail_on/warn_on; it is still
			// checked as a budget key below, where it means nothing.
			if err := (Config{FailOn: "", WarnOn: ""}).Validate(); err != nil {
				t.Errorf("unset thresholds must be valid, got %v", err)
			}
		} else {
			if err := (Config{FailOn: sev}).Validate(); err == nil {
				t.Errorf("Config{FailOn: %q}.Validate() = nil, want rejection — a typo'd fail_on silently disables the gate", sev)
			}
			if err := (Config{WarnOn: sev}).Validate(); err == nil {
				t.Errorf("Config{WarnOn: %q}.Validate() = nil, want rejection", sev)
			}
		}

		if err := (Config{Budget: map[findings.Severity]int{sev: 1}}).Validate(); err == nil {
			t.Errorf("Config{Budget: {%q: 1}}.Validate() = nil, want rejection — a budget under an unrecognised key is never consulted, so the real severity keeps its default budget of 0 while the operator believes they set one", sev)
		}
	}

	// Every defined severity must be accepted in every slot, or validation
	// would have turned into its own outage.
	for _, sev := range findings.SeverityOrder {
		cfg := Config{FailOn: sev, WarnOn: sev, Budget: map[findings.Severity]int{sev: 3}}
		if err := cfg.Validate(); err != nil {
			t.Errorf("Config with severity %q rejected: %v", sev, err)
		}
	}

	// The error must name the offending key so an operator can find it.
	err := (Config{FailOn: "High"}).Validate()
	if err == nil || !strings.Contains(err.Error(), "fail_on") {
		t.Errorf("rejection must name fail_on, got %v", err)
	}
}

// TestFailClosed_GateMatrixFailsExactlyWhenThresholdIsMet drives Evaluate over
// every (finding severity × fail_on) pair and derives the expectation from
// meetsThreshold rather than restating it.
//
// This is the gate's whole job in one table: a finding at or above the
// threshold MUST produce Pass=false with a non-zero exit code, and one below it
// MUST NOT. Pinning both directions matters — a gate that fails on everything
// is as useless as one that fails on nothing, because operators disable it.
func TestFailClosed_GateMatrixFailsExactlyWhenThresholdIsMet(t *testing.T) {
	t.Parallel()

	for _, threshold := range findings.SeverityOrder {
		for _, sev := range findings.SeverityOrder {
			r := Evaluate(Config{FailOn: threshold}, []findings.Finding{failClosedFinding(sev)})

			wantFail := meetsThreshold(sev, threshold)
			if r.Pass == wantFail {
				t.Errorf("fail_on=%s with a %s finding: Pass=%v, want %v", threshold, sev, r.Pass, !wantFail)
			}
			if wantFail && r.ExitCode == 0 {
				t.Errorf("fail_on=%s with a %s finding: exit 0 on a failing gate — a non-zero code is the only thing CI reads", threshold, sev)
			}
			if !wantFail && r.ExitCode != 0 {
				t.Errorf("fail_on=%s with a %s finding: exit %d, want 0", threshold, sev, r.ExitCode)
			}
		}
	}

	// The headline case stated on its own, because it is the one every user
	// assumes works.
	r := Evaluate(Config{FailOn: findings.SeverityCritical}, []findings.Finding{failClosedFinding(findings.SeverityCritical)})
	if r.Pass || r.ExitCode == 0 {
		t.Fatalf("a critical finding under fail_on=critical must fail: Pass=%v exit=%d", r.Pass, r.ExitCode)
	}
}

// TestFailClosed_UnsetFailOnGatesEveryNewFinding pins the documented default.
//
// With no explicit threshold, Evaluate gates EVERY new finding — the strictest
// possible reading, and the fail-closed one. It is worth pinning precisely
// because the tempting "sensible" default is the opposite: treating an unset
// threshold as "gate nothing" would turn a config with a forgotten fail_on into
// a scanner that reports pass no matter what it found. Note that core/scan.go
// only reaches Evaluate at all once a policy is configured somehow (fail_on,
// baseline_mode, or a budget), so this default applies to a gate that was asked
// for, not to an unconfigured project.
func TestFailClosed_UnsetFailOnGatesEveryNewFinding(t *testing.T) {
	t.Parallel()

	for _, sev := range findings.SeverityOrder {
		r := Evaluate(Config{}, []findings.Finding{failClosedFinding(sev)})
		if r.Pass || r.ExitCode == 0 {
			t.Errorf("fail_on unset with a %s finding: Pass=%v exit=%d, want a failure — an unset threshold gates everything", sev, r.Pass, r.ExitCode)
		}
	}

	// A budget still applies without a threshold: the gate is strict, not blind.
	r := Evaluate(Config{Budget: map[findings.Severity]int{findings.SeverityInfo: 1}},
		[]findings.Finding{failClosedFinding(findings.SeverityInfo)})
	if !r.Pass {
		t.Errorf("one info finding inside an info budget of 1 must pass, got %q", r.Summary)
	}
}

// TestFailClosed_MaxSeverityNeverElectsAnUnknown guards the baseline-strict
// path, whose fail decision hangs entirely on maxSeverity.
//
// An undefined severity must not be returned as "most severe": were it, the
// baseline gate would then compare that unknown against fail_on, meetsThreshold
// would answer false, and a baseline holding a real critical would be reported
// as clean because a junk value out-ranked it.
func TestFailClosed_MaxSeverityNeverElectsAnUnknown(t *testing.T) {
	t.Parallel()

	for _, unknown := range failClosedUndefinedSeverities {
		if got := maxSeverity([]findings.Finding{failClosedFinding(unknown)}); got != "" {
			t.Errorf("maxSeverity([%q]) = %q, want \"\" — an unrecognised severity is not a severity", unknown, got)
		}

		for _, sev := range findings.SeverityOrder {
			ff := []findings.Finding{failClosedFinding(unknown), failClosedFinding(sev)}
			if got := maxSeverity(ff); got != sev {
				t.Errorf("maxSeverity([%q, %q]) = %q, want %q — the unknown must never outrank a real level", unknown, sev, got, sev)
			}
			// Order must not matter either.
			ff = []findings.Finding{failClosedFinding(sev), failClosedFinding(unknown)}
			if got := maxSeverity(ff); got != sev {
				t.Errorf("maxSeverity([%q, %q]) = %q, want %q", sev, unknown, got, sev)
			}
		}
	}

	// Over the full ladder the answer is the top of it, whatever the input order.
	all := make([]findings.Finding, 0, len(findings.SeverityOrder))
	for i := len(findings.SeverityOrder) - 1; i >= 0; i-- {
		all = append(all, failClosedFinding(findings.SeverityOrder[i]))
	}
	if got := maxSeverity(all); got != findings.SeverityCritical {
		t.Errorf("maxSeverity(all severities) = %q, want critical", got)
	}
	if got := maxSeverity(nil); got != "" {
		t.Errorf("maxSeverity(nil) = %q, want \"\"", got)
	}
}

// TestFailClosed_EmptyInputsPassWithoutPanicking checks the other half of
// fail-closed: refusing to pass when it cannot evaluate must not become
// refusing to pass when there is genuinely nothing to evaluate. A gate that
// fails on an empty scan gets switched off within a day, taking the real gate
// with it.
func TestFailClosed_EmptyInputsPassWithoutPanicking(t *testing.T) {
	t.Parallel()

	configs := []Config{
		{},
		{FailOn: findings.SeverityCritical},
		{FailOn: findings.SeverityInfo, WarnOn: findings.SeverityInfo},
		{BaselineMode: BaselineModeStrict},
		{BaselineMode: BaselineModeWarn},
		{BaselineMode: BaselineModeOff},
		{FailOn: findings.SeverityHigh, BaselineMode: BaselineModeStrict, Budget: map[findings.Severity]int{}},
		{Budget: nil},
	}
	inputs := [][]findings.Finding{nil, {}}

	for _, cfg := range configs {
		for _, in := range inputs {
			r := Evaluate(cfg, in)
			if r == nil {
				t.Fatalf("Evaluate(%+v, %v) returned nil", cfg, in)
			}
			if !r.Pass || r.ExitCode != 0 {
				t.Errorf("Evaluate(%+v, %v): Pass=%v exit=%d, want a clean pass — nothing was found, so nothing failed",
					cfg, in, r.Pass, r.ExitCode)
			}
			if !strings.Contains(r.Summary, "pass") {
				t.Errorf("Evaluate(%+v, %v) summary = %q, want it to say pass", cfg, in, r.Summary)
			}
			if len(r.New) != 0 || len(r.Baselined) != 0 || len(r.Suppressed) != 0 {
				t.Errorf("Evaluate(%+v, %v) invented findings: %+v", cfg, in, r)
			}
		}
	}
}

// TestFailClosed_AFailingSummaryNamesTheFindingThatFailedIt is a fail-closed
// assertion about the OUTPUT, not the verdict: a gate that fails without saying
// what failed it trains operators to treat the failure as noise, which is the
// slow path to the same false all-clear.
func TestFailClosed_AFailingSummaryNamesTheFindingThatFailedIt(t *testing.T) {
	t.Parallel()

	r := Evaluate(Config{FailOn: findings.SeverityHigh}, []findings.Finding{
		failClosedFinding(findings.SeverityLow),
		failClosedFinding(findings.SeverityCritical),
	})
	if r.Pass {
		t.Fatalf("a critical finding under fail_on=high must fail, got %q", r.Summary)
	}
	for _, want := range []string{"fail", "critical", "NOX-FAILCLOSED-001", "app/main.go"} {
		if !strings.Contains(r.Summary, want) {
			t.Errorf("summary %q must mention %q", r.Summary, want)
		}
	}
	if strings.Contains(r.Summary, "low") {
		t.Errorf("summary %q names a finding that gated nothing", r.Summary)
	}
}

// TestFailClosed_UndefinedSeverityFindingMustNotSlipTheGate is SKIPPED: it
// asserts the behaviour nox should have, and today does not.
//
// PRODUCT BUG (fail-open). Evaluate gates a severity only when
// `cfg.FailOn == "" || meetsThreshold(sev, cfg.FailOn)`. meetsThreshold answers
// false for a severity it does not recognise, so with any fail_on configured a
// finding carrying an undefined severity is gated by NOTHING and the run exits
// 0 — the gate silently drops the one finding it could not classify, and
// reports pass.
//
// It is reachable from configuration, not just from the API. core/scan.go
// applies `scan.rules.severity_override` and `scan.conditional_severity` by
// casting the raw YAML string straight to findings.Severity with no
// validation anywhere on the path:
//
//	scan:
//	  rules:
//	    severity_override:
//	      NOX-S001: Critical      # capitalized — now an undefined severity
//
// The operator intended to RAISE that rule to critical. What they get is a
// finding no gate can see. Same shape as the risk-class ordinal that mapped ""
// to "passive": an unclassifiable value inheriting a permissive default.
//
// The fail-closed fix belongs upstream of this package — validate the override
// severities at config load, the way policy.Config.Validate already rejects a
// typo'd fail_on — and defensively here: a finding whose severity is not a
// defined level should be treated as gated regardless of the threshold, so the
// gate can never pass something it could not rank.
//
// FIXED: Evaluate now gates an unrecognised severity unconditionally
// (`!sev.IsValid()`), so a finding nox cannot rank can no longer slip the gate.
// This test is the regression guard for that.
func TestFailClosed_UndefinedSeverityFindingMustNotSlipTheGate(t *testing.T) {

	for _, unknown := range failClosedUndefinedSeverities {
		for _, threshold := range findings.SeverityOrder {
			r := Evaluate(Config{FailOn: threshold}, []findings.Finding{failClosedFinding(unknown)})
			if r.Pass || r.ExitCode == 0 {
				t.Errorf("fail_on=%s with a finding of undefined severity %q: Pass=%v exit=%d — a gate that cannot rank a finding must not pass it",
					threshold, unknown, r.Pass, r.ExitCode)
			}
		}
	}
}
