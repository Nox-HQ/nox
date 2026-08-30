// Package policy evaluates scan findings against configurable thresholds to
// determine pass/fail outcomes for CI pipelines.
package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/capability"
	"github.com/nox-hq/nox/core/findings"
)

// BaselineMode controls how baselined findings affect policy evaluation.
type BaselineMode string

const (
	// BaselineModeStrict counts baselined findings toward failure.
	BaselineModeStrict BaselineMode = "strict"
	// BaselineModeWarn treats baselined findings as warnings only.
	BaselineModeWarn BaselineMode = "warn"
	// BaselineModeOff disables baseline handling in policy evaluation.
	BaselineModeOff BaselineMode = "off"
)

// Config defines the policy evaluation parameters.
type Config struct {
	FailOn       findings.Severity `yaml:"fail_on"`
	WarnOn       findings.Severity `yaml:"warn_on"`
	BaselineMode BaselineMode      `yaml:"baseline_mode"`
	// Budget is a per-severity allowance for NEW findings: the gate tolerates up
	// to Budget[severity] new findings of that severity before failing. Absent
	// entries default to 0 (fail on the first), so an empty Budget reproduces
	// the pre-budget max-severity gate exactly.
	Budget map[findings.Severity]int `yaml:"budget"`

	// Uncertainty says what to do about what nox did not establish. It gates
	// the second axis the policy has never read: not how bad a finding would be
	// if true, but how much nox actually determined. Defaults to warn.
	Uncertainty Uncertainty `yaml:"uncertainty"`

	// RequireCapabilities lists the analysis capabilities this project's triage
	// depends on. Empty by default, which is every existing repository and
	// changes nothing for them. A project that lists one is asserting it relies
	// on that question being answered, and will be told when it stops being.
	//
	// Deliberately a declaration rather than an inference: see
	// EvaluateCapabilities for why "fail on anything unevaluated" cannot be the
	// design.
	RequireCapabilities []string `yaml:"require_capabilities"`
}

// Validate rejects a policy configuration whose gate keywords are not
// recognized values.
//
// This exists because an unrecognized fail_on silently DISABLES the gate rather
// than failing loudly: meetsThreshold returns false for a severity it does not
// know, so every finding is treated as un-gated and a scan with critical
// findings exits 0. A capitalized "High", a trailing space, or a typo therefore
// turns the primary CI gate off with no signal — strictly worse than having no
// policy at all, because it looks configured. The severity comparison is
// case-sensitive and lowercase-only, so the value must match exactly.
func (c Config) Validate() error {
	if c.FailOn != "" {
		if !c.FailOn.IsValid() {
			return fmt.Errorf("policy.fail_on: %q is not a valid severity (want one of critical, high, medium, low, info)", c.FailOn)
		}
	}
	if c.WarnOn != "" {
		if !c.WarnOn.IsValid() {
			return fmt.Errorf("policy.warn_on: %q is not a valid severity (want one of critical, high, medium, low, info)", c.WarnOn)
		}
	}
	// An unrecognised uncertainty mode must not silently pick a behaviour. The
	// same reasoning as fail_on above: a mistyped value that quietly resolves
	// to the permissive default looks configured and is not.
	if !c.Uncertainty.Valid() {
		return fmt.Errorf("policy.uncertainty: %q is not valid (want one of warn, fail, ignore)", c.Uncertainty)
	}
	for _, name := range c.RequireCapabilities {
		if !capability.AnalysisCapability(name).Valid() {
			return fmt.Errorf("policy.require_capabilities: %q is not a known analysis capability "+
				"(run `nox analysis-capabilities` for the list)", name)
		}
	}
	switch c.BaselineMode {
	case "", BaselineModeStrict, BaselineModeWarn, BaselineModeOff:
	default:
		return fmt.Errorf("policy.baseline_mode: %q is not valid (want one of strict, warn, off)", c.BaselineMode)
	}
	for sev := range c.Budget {
		if !sev.IsValid() {
			return fmt.Errorf("policy.budget: %q is not a valid severity key (want one of critical, high, medium, low, info)", sev)
		}
	}
	return nil
}

// Result holds the outcome of a policy evaluation.
type Result struct {
	Pass      bool
	ExitCode  int
	New       []findings.Finding
	Baselined []findings.Finding
	// Suppressed holds inline-suppressed (nox:ignore) and VEX-cleared findings.
	// They are excluded from the fail-on gate.
	Suppressed []findings.Finding
	Warnings   []string
	Summary    string
}

// Evaluate applies policy rules to the given findings and returns the result.
func Evaluate(cfg Config, all []findings.Finding) *Result {
	r := &Result{Pass: true, ExitCode: 0}

	for i := range all {
		finding := all[i]
		switch {
		case finding.Status == findings.StatusBaselined:
			r.Baselined = append(r.Baselined, finding)
		case !finding.Status.IsActive():
			// Inline-suppressed (nox:ignore) and VEX-cleared findings are not
			// active and must never count toward the fail-on gate. Previously
			// these fell through to r.New, so a suppressed High failed CI.
			r.Suppressed = append(r.Suppressed, finding)
		default:
			r.New = append(r.New, finding)
		}
	}

	// Check new findings against the fail threshold, honoring per-severity
	// budgets. A severity is gated when there is no explicit threshold (every
	// new finding gated) or the severity meets fail_on. A gated severity fails
	// only once its new-finding count exceeds its budget (default 0). With an
	// empty budget this is identical to the previous "any new finding at/above
	// fail_on fails" gate.
	for sev, n := range findings.CountBySeverity(r.New) {
		// An unrecognised severity is gated unconditionally.
		//
		// meetsThreshold refuses to rank a severity it does not know, so
		// without this branch a finding carrying an undefined severity
		// satisfied no threshold and slipped EVERY gate — the run exited 0 on
		// the one finding it could not classify. That is reachable from
		// configuration, not just the API: a `severity_override` of "Critical"
		// (capitalised) is cast straight to a Severity, and rather than raising
		// the rule it made the finding invisible to the gate.
		//
		// Fail closed: if nox cannot tell how severe something is, it does not
		// get to decide the finding is unimportant.
		gated := cfg.FailOn == "" || !sev.IsValid() || meetsThreshold(sev, cfg.FailOn)
		if gated && n > cfg.Budget[sev] {
			r.Pass = false
			r.ExitCode = 1
			if cfg.Budget[sev] > 0 {
				r.Warnings = append(r.Warnings, fmt.Sprintf(
					"%d new %s finding(s) exceed the budget of %d", n, sev, cfg.Budget[sev]))
			}
		}
	}

	// Handle baselined findings per mode.
	switch cfg.BaselineMode {
	case BaselineModeStrict:
		if cfg.FailOn != "" {
			maxBaselined := maxSeverity(r.Baselined)
			if maxBaselined != "" && meetsThreshold(maxBaselined, cfg.FailOn) {
				r.Pass = false
				r.ExitCode = 1
			}
		} else if len(r.Baselined) > 0 {
			r.Pass = false
			r.ExitCode = 1
		}
	case BaselineModeWarn:
		if len(r.Baselined) > 0 {
			r.Warnings = append(r.Warnings, fmt.Sprintf("%d baselined finding(s) still present", len(r.Baselined)))
		}
	}

	// Check warnings threshold.
	if cfg.WarnOn != "" {
		for i := range r.New {
			finding := r.New[i]
			if meetsThreshold(finding.Severity, cfg.WarnOn) && !meetsThreshold(finding.Severity, cfg.FailOn) {
				r.Warnings = append(r.Warnings, fmt.Sprintf("warning: %s finding %s in %s",
					finding.Severity, finding.RuleID, finding.Location.FilePath))
			}
		}
	}

	// Build summary.
	var parts []string
	parts = append(parts, fmt.Sprintf("%d new", len(r.New)))
	if len(r.Baselined) > 0 {
		parts = append(parts, fmt.Sprintf("%d baselined", len(r.Baselined)))
	}
	if r.Pass {
		r.Summary = fmt.Sprintf("policy: pass (%s)", strings.Join(parts, ", "))
	} else {
		// A failure names what failed it. "policy: fail (70 new, 753
		// baselined)" states two counts and omits the only fact the reader
		// needs, and the counts actively mislead: most of those new findings
		// are below fail_on and gate nothing, so a large number next to the
		// word "fail" reads as a systemic problem rather than as one finding
		// somebody just introduced. Observed doing exactly that — the count
		// sent a reader off to hunt for baseline drift that did not exist,
		// while the single critical that failed the run went unmentioned.
		r.Summary = fmt.Sprintf("policy: fail (%s)%s", strings.Join(parts, ", "), gatingSuffix(r, cfg))
	}

	return r
}

// gatingSuffix names the findings that failed the policy.
//
// Bounded at three, with a count for the rest: the point is to identify the
// problem, and a wall of findings pushes the summary off the top of a CI log
// as surely as saying nothing does.
func gatingSuffix(r *Result, cfg Config) string {
	gating := gatingFindings(r, cfg)
	if len(gating) == 0 {
		// The baseline modes fail without any new finding to point at. Saying
		// nothing is right there — the existing warnings already explain it.
		return ""
	}

	const show = 3
	shown := gating
	if len(shown) > show {
		shown = shown[:show]
	}

	named := make([]string, 0, len(shown))
	for i := range shown {
		f := shown[i]
		where := f.Location.FilePath
		if f.Location.StartLine > 0 {
			where = fmt.Sprintf("%s:%d", where, f.Location.StartLine)
		}
		named = append(named, fmt.Sprintf("%s %s at %s", f.Severity, f.RuleID, where))
	}

	suffix := " — " + strings.Join(named, "; ")
	if rest := len(gating) - len(shown); rest > 0 {
		suffix += fmt.Sprintf("; and %d more", rest)
	}
	return suffix
}

// gatingFindings are the new findings that actually failed the gate: the ones
// at or above fail_on, in severity order so the worst is named first.
func gatingFindings(r *Result, cfg Config) []findings.Finding {
	var out []findings.Finding
	for i := range r.New {
		f := r.New[i]
		if cfg.FailOn == "" || meetsThreshold(f.Severity, cfg.FailOn) {
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return findings.SeverityRank(out[i].Severity) < findings.SeverityRank(out[j].Severity)
	})
	return out
}

// severityRankOK returns a severity's rank and whether it is a defined level,
// keeping the gate's comparisons on the one canonical ranking in core/findings.
func severityRankOK(s findings.Severity) (int, bool) {
	return findings.SeverityRank(s), s.IsValid()
}

// meetsThreshold returns true if severity is at or above the threshold.
func meetsThreshold(severity, threshold findings.Severity) bool {
	sr, ok1 := severityRankOK(severity)
	tr, ok2 := severityRankOK(threshold)
	if !ok1 || !ok2 {
		return false
	}
	return sr <= tr
}

// maxSeverity returns the most severe severity in the given findings.
func maxSeverity(ff []findings.Finding) findings.Severity {
	best := findings.Severity("")
	bestRank := 999
	for i := range ff {
		finding := ff[i]
		r, ok := severityRankOK(finding.Severity)
		if ok && r < bestRank {
			bestRank = r
			best = finding.Severity
		}
	}
	return best
}
