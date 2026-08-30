package policy_test

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/capability"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/policy"
)

// gate is a CapabilityGate stating exactly the case a test means, rather than
// assembling an installation to imply it.
type gate map[capability.AnalysisCapability]bool

func (g gate) Provided(c capability.AnalysisCapability) bool { return g[c] }

// Answered lets the same fixture stand for both halves of the decision: a
// capability this installation provides is treated as having concluded once.
// That keeps every test below meaning what it meant before the run view
// existed — "provided" was the whole question then — while the run-specific
// cases state their own counts explicitly.
func (g gate) Answered(c capability.AnalysisCapability) (answered, inconclusive int) {
	if g[c] {
		return 1, 0
	}
	return 0, 0
}

// run states a run view directly, for the cases where provided and answered
// come apart. The pair is (answered, inconclusive).
type run map[capability.AnalysisCapability][2]int

func (r run) Answered(c capability.AnalysisCapability) (answered, inconclusive int) {
	v := r[c]
	return v[0], v[1]
}

func highFinding() findings.Finding {
	return findings.Finding{
		RuleID: "SEC-003", Severity: findings.SeverityHigh,
		Location: findings.Location{FilePath: "app/creds.py", StartLine: 1},
	}
}

// TestNoAdoptionCliff is the most important test in this file.
//
// Making uncertainty fail-closed by default would turn red, on upgrade, every
// repository gated on a severity threshold — which is most of them. A gate
// everybody switches off within the hour protects nothing, so the default has
// to be inert, and "inert" has to be asserted rather than believed.
func TestNoAdoptionCliff(t *testing.T) {
	before := policy.Evaluate(policy.Config{FailOn: findings.SeverityCritical},
		[]findings.Finding{highFinding()})

	// The same config a repository already has, evaluated through the new path
	// against an installation that provides nothing at all.
	after := policy.EvaluateCapabilities(
		policy.Config{FailOn: findings.SeverityCritical}, gate{}, gate{},
		policy.Evaluate(policy.Config{FailOn: findings.SeverityCritical},
			[]findings.Finding{highFinding()}))

	if after.Pass != before.Pass || after.ExitCode != before.ExitCode {
		t.Errorf("an unchanged config changed outcome: pass %v->%v, exit %d->%d",
			before.Pass, after.Pass, before.ExitCode, after.ExitCode)
	}
	if len(after.Warnings) != len(before.Warnings) {
		t.Errorf("an unchanged config gained %d warning(s); a project that declared "+
			"no capability requirement must hear nothing",
			len(after.Warnings)-len(before.Warnings))
	}
}

// TestUnmetRequirementWarnsByDefaultAndNamesTheFlag. §1.5 of the design doc
// requires a release in which the stricter behaviour is announced by the
// warning that precedes it, so switching the default later surprises nobody.
func TestUnmetRequirementWarnsByDefaultAndNamesTheFlag(t *testing.T) {
	cfg := policy.Config{
		FailOn:              findings.SeverityCritical,
		RequireCapabilities: []string{"reachability"},
	}
	r := policy.EvaluateCapabilities(cfg, gate{}, gate{}, policy.Evaluate(cfg, nil))

	if !r.Pass {
		t.Error("the default mode failed the build; warn must not gate")
	}
	if len(r.Warnings) == 0 {
		t.Fatal("an unmet requirement produced no warning")
	}
	joined := strings.Join(r.Warnings, " ")
	if !strings.Contains(joined, "reachability") {
		t.Errorf("the warning does not name the missing capability: %q", joined)
	}
	if !strings.Contains(joined, "policy.uncertainty=fail") {
		t.Errorf("the warning does not name the flag that would gate on it: %q", joined)
	}
	// The wording has to stop a reader concluding the finding was cleared.
	if !strings.Contains(joined, "unevaluated, not cleared") {
		t.Errorf("the warning does not distinguish unevaluated from cleared: %q", joined)
	}
}

// TestFailModeGatesOnAnUnmetRequirement is Track D's exit criterion: losing an
// analyzer the project declared it depends on cannot make the build greener.
func TestFailModeGatesOnAnUnmetRequirement(t *testing.T) {
	cfg := policy.Config{
		FailOn:              findings.SeverityCritical,
		Uncertainty:         policy.UncertaintyFail,
		RequireCapabilities: []string{"reachability"},
	}

	// With the capability present, a clean scan passes.
	present := policy.EvaluateCapabilities(cfg,
		gate{capability.Reachability: true}, gate{capability.Reachability: true}, policy.Evaluate(cfg, nil))
	if !present.Pass {
		t.Fatalf("a met requirement failed the build: %+v", present.Warnings)
	}

	// Uninstall the analyzer and the same clean scan does NOT go green.
	absent := policy.EvaluateCapabilities(cfg, gate{}, gate{}, policy.Evaluate(cfg, nil))
	if absent.Pass {
		t.Error("removing a required analyzer left the build passing — the exact " +
			"failure this setting exists to close")
	}
	if absent.ExitCode == 0 {
		t.Error("the build failed but exited 0")
	}
	if !strings.Contains(absent.Summary, "fail") {
		t.Errorf("summary %q does not report the failure", absent.Summary)
	}
}

// TestIgnoreIsSilent. An operator who has genuinely decided they do not want
// this signal should be able to turn it off, rather than learning to skim past
// a warning — a warning always ignored trains a reader to ignore its
// neighbours too.
func TestIgnoreIsSilent(t *testing.T) {
	cfg := policy.Config{
		Uncertainty:         policy.UncertaintyIgnore,
		RequireCapabilities: []string{"reachability", "call_graph"},
	}
	r := policy.EvaluateCapabilities(cfg, gate{}, gate{}, policy.Evaluate(cfg, nil))
	if !r.Pass {
		t.Error("ignore mode failed the build")
	}
	if len(r.Warnings) != 0 {
		t.Errorf("ignore mode emitted %d warning(s)", len(r.Warnings))
	}
}

// TestAMistypedSettingIsRejectedNotGuessed. The reasoning is the one already
// written for fail_on: a value that quietly resolves to the permissive default
// looks configured and is not, which is strictly worse than having no policy.
func TestAMistypedSettingIsRejectedNotGuessed(t *testing.T) {
	for _, bad := range []string{"Fail", "FAIL", "strict", "true", "yes", " fail"} {
		cfg := policy.Config{Uncertainty: policy.Uncertainty(bad)}
		if err := cfg.Validate(); err == nil {
			t.Errorf("policy.uncertainty=%q was accepted; a mistyped mode must be "+
				"rejected rather than resolved to the permissive default", bad)
		}
	}
	for _, good := range []string{"", "warn", "fail", "ignore"} {
		if err := (policy.Config{Uncertainty: policy.Uncertainty(good)}).Validate(); err != nil {
			t.Errorf("policy.uncertainty=%q was rejected: %v", good, err)
		}
	}

	// The same for a capability nobody defines: silently accepting it would
	// declare a requirement that can never be met and never be reported.
	bad := policy.Config{RequireCapabilities: []string{"solves_halting_problem"}}
	if err := bad.Validate(); err == nil {
		t.Error("an undefined capability was accepted in require_capabilities")
	}
	good := policy.Config{RequireCapabilities: []string{"reachability", "taint"}}
	if err := good.Validate(); err != nil {
		t.Errorf("a valid requirement was rejected: %v", err)
	}
}

// TestFailModePreservesAnExistingFailure. Folding the capability verdict into
// an existing Result must not overwrite why the build was already failing.
func TestFailModePreservesAnExistingFailure(t *testing.T) {
	cfg := policy.Config{
		FailOn:              findings.SeverityHigh,
		Uncertainty:         policy.UncertaintyFail,
		RequireCapabilities: []string{"reachability"},
	}
	base := policy.Evaluate(cfg, []findings.Finding{highFinding()})
	if base.Pass {
		t.Fatal("a high finding at fail_on=high did not fail; the fixture is wrong")
	}
	r := policy.EvaluateCapabilities(cfg, gate{}, gate{}, base)

	if r.Pass {
		t.Error("the combined result passed")
	}
	if !strings.Contains(r.Summary, "SEC-003") && !strings.Contains(r.Summary, "high") {
		t.Errorf("summary %q lost the finding that was already failing the gate", r.Summary)
	}
	if !strings.Contains(r.Summary, "capability") {
		t.Errorf("summary %q does not mention the unmet requirement", r.Summary)
	}
}

// TestNilGateIsTreatedAsProvidingNothing. A caller that forgot to pass a
// registry must not be handed a pass; the honest reading of "no registry" is
// "nothing is known to be provided".
func TestNilGateIsTreatedAsProvidingNothing(t *testing.T) {
	cfg := policy.Config{
		Uncertainty:         policy.UncertaintyFail,
		RequireCapabilities: []string{"reachability"},
	}
	r := policy.EvaluateCapabilities(cfg, nil, nil, policy.Evaluate(cfg, nil))
	if r.Pass {
		t.Error("a nil capability gate passed a declared requirement")
	}
}

// TestValidationSeesEveryGateField guards the defect this file's own
// development produced.
//
// The uncertainty validation was written correctly and was unreachable: the
// loader built its policy.Config from a separate literal that omitted the new
// fields, so `uncertainty: Fail` was accepted and silently resolved to the
// permissive default — precisely the failure the fail_on validation exists to
// prevent, reproduced one field over. A validator that cannot see a field
// validates nothing about it, and two struct literals side by side make that
// invisible.
//
// This asserts the property directly: every gate-affecting field must be
// rejectable. If a future field is added to Config and not to whatever builds
// it, this is the test that should notice.
func TestValidationSeesEveryGateField(t *testing.T) {
	cases := []struct {
		field string
		cfg   policy.Config
	}{
		{"fail_on", policy.Config{FailOn: findings.Severity("High")}},
		{"warn_on", policy.Config{WarnOn: findings.Severity("Medium")}},
		{"baseline_mode", policy.Config{BaselineMode: policy.BaselineMode("Strict")}},
		{"budget", policy.Config{Budget: map[findings.Severity]int{"Critical": 1}}},
		{"uncertainty", policy.Config{Uncertainty: policy.Uncertainty("Fail")}},
		{"require_capabilities", policy.Config{RequireCapabilities: []string{"reachabilty"}}},
	}
	for _, tc := range cases {
		if err := tc.cfg.Validate(); err == nil {
			t.Errorf("policy.%s accepted an invalid value; a gate keyword that "+
				"silently resolves to a default is worse than no policy at all", tc.field)
		}
	}
}

// TestTheThreeWaysARequirementGoesUnmetAreWordedApart checks that each way a
// requirement can go unmet reads differently to the operator.
//
// Unsupported, inconclusive and unexercised all fail the gate, and all three
// need a different action from the reader: install a plugin, look at why the
// analysis could not tell, or find out why nothing put the question. A single
// "not provided by this installation" sent an operator to install something
// they already had.
//
// The inconclusive case is the one Track H is about. An intelligence service
// that answers slowly or partially leaves capabilities recorded as Unknown, and
// a gate that accepted "we asked and could not tell" as satisfaction of "this
// must be determined" would be the false all-clear rebuilt one layer up. That
// branch had no test until reversing it in the implementation changed nothing
// anywhere.
func TestTheThreeWaysARequirementGoesUnmetAreWordedApart(t *testing.T) {
	base := policy.Config{Uncertainty: policy.UncertaintyFail}

	t.Run("unsupported", func(t *testing.T) {
		cfg := base
		cfg.RequireCapabilities = []string{"call_graph"}
		r := policy.EvaluateCapabilities(cfg, gate{}, run{}, policy.Evaluate(cfg, nil))
		assertUnmet(t, r, "call_graph", "not provided by this installation")
	})

	t.Run("inconclusive", func(t *testing.T) {
		cfg := base
		cfg.RequireCapabilities = []string{"reachability"}
		r := policy.EvaluateCapabilities(cfg,
			gate{capability.Reachability: true},
			run{capability.Reachability: {0, 3}},
			policy.Evaluate(cfg, nil))
		assertUnmet(t, r, "reachability", "could not determine")
		if strings.Contains(joinWarnings(r), "not provided by this installation") {
			t.Error("a capability that ran and could not tell was reported as absent " +
				"from the installation; the operator would go and install it again")
		}
	})

	t.Run("unexercised", func(t *testing.T) {
		cfg := base
		cfg.RequireCapabilities = []string{"reachability"}
		r := policy.EvaluateCapabilities(cfg,
			gate{capability.Reachability: true},
			run{capability.Reachability: {0, 0}},
			policy.Evaluate(cfg, nil))
		assertUnmet(t, r, "reachability", "nothing in this scan put the question")
	})

	t.Run("answered satisfies", func(t *testing.T) {
		cfg := base
		cfg.RequireCapabilities = []string{"reachability"}
		r := policy.EvaluateCapabilities(cfg,
			gate{capability.Reachability: true},
			run{capability.Reachability: {1, 9}},
			policy.Evaluate(cfg, nil))
		if !r.Pass {
			t.Errorf("a capability that concluded about one subject failed its "+
				"requirement: %v. Nine inconclusive results alongside one real answer "+
				"is a normal scan, not an unmet dependency", r.Warnings)
		}
	})
}

func joinWarnings(r *policy.Result) string { return strings.Join(r.Warnings, " ") }

func assertUnmet(t *testing.T, r *policy.Result, capName, want string) {
	t.Helper()
	if r.Pass {
		t.Fatalf("an unmet requirement for %s passed the gate", capName)
	}
	got := joinWarnings(r)
	if !strings.Contains(got, capName) {
		t.Errorf("the warning does not name %s: %q", capName, got)
	}
	if !strings.Contains(got, want) {
		t.Errorf("the warning does not say %q, so the reader cannot tell which of the "+
			"three ways this went unmet: %q", want, got)
	}
}
