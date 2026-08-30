package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/capability"
)

// Uncertainty says what a build should do about what nox did not establish.
//
// The gate nox has always had reads severity: how bad this would be if true.
// It has never read the other axis — how much nox actually determined — and
// that axis is where the dangerous failure lives. Uninstall the reachability
// plugin and every finding it would have classified simply stops being
// classified. Nothing goes red. The build is greener than it was, and it is
// greener because nox now knows less.
type Uncertainty string

// Uncertainty modes.
const (
	// UncertaintyWarn reports what was not evaluated and does not gate. The
	// default, and deliberately so — see RequireCapabilities for why the
	// stricter setting cannot be the default yet.
	UncertaintyWarn Uncertainty = "warn"
	// UncertaintyFail treats an unmet capability requirement as a failure.
	UncertaintyFail Uncertainty = "fail"
	// UncertaintyIgnore says nothing at all. It exists because an operator who
	// has genuinely decided they do not want this signal should be able to turn
	// it off explicitly, rather than learning to skim past a warning — a
	// warning that is always ignored is worse than one that was never printed,
	// because it trains the reader to ignore its neighbours too.
	UncertaintyIgnore Uncertainty = "ignore"
)

// Valid reports whether u is a defined mode. The empty string is valid and
// means the default.
func (u Uncertainty) Valid() bool {
	switch u {
	case "", UncertaintyWarn, UncertaintyFail, UncertaintyIgnore:
		return true
	}
	return false
}

// Effective resolves the zero value to the default.
func (u Uncertainty) Effective() Uncertainty {
	if u == "" {
		return UncertaintyWarn
	}
	return u
}

// CapabilityGate is the capability half of a policy decision.
//
// It is a small interface rather than a *capability.Registry so core/policy
// does not have to import the registry's whole world, and so a test can state
// the case it means in one line instead of assembling an installation.
type CapabilityGate interface {
	// Provided reports whether anything on this installation offers c.
	Provided(c capability.AnalysisCapability) bool
}

// EvaluateCapabilities checks a project's declared capability requirements
// against what the installation actually provides, and folds the outcome into
// an existing policy Result.
//
// # Why requirements are declared rather than inferred
//
// The obvious design is to fail whenever anything is unevaluated. It cannot be
// the design. Every scan today has three capabilities with no implementation —
// constant evaluation, call graphs, entry points — so "fail on any gap" turns
// every build on earth red on upgrade, and the setting gets switched off within
// the hour. A gate everybody disables protects nothing.
//
// So the project says what it depends on. An empty list changes nothing, which
// is what every existing repository has. A repository that lists reachability
// is asserting that its triage depends on reachability being answered, and nox
// will tell it — loudly, and at `fail` fatally — when that stops being true.
// That is the narrow, real case: not "nox does not know everything", but
// "nox stopped knowing something this project was relying on".
func EvaluateCapabilities(cfg Config, gate CapabilityGate, r *Result) *Result {
	if r == nil {
		r = &Result{Pass: true, ExitCode: 0}
	}
	mode := cfg.Uncertainty.Effective()
	if mode == UncertaintyIgnore || len(cfg.RequireCapabilities) == 0 {
		return r
	}

	var missing []string
	for _, name := range cfg.RequireCapabilities {
		c := capability.AnalysisCapability(name)
		if gate != nil && gate.Provided(c) {
			continue
		}
		missing = append(missing, name)
	}
	if len(missing) == 0 {
		return r
	}
	sort.Strings(missing)

	// The wording carries the whole point. An operator who reads this as "nox
	// is missing a feature" has drawn the wrong conclusion; what it means is
	// that findings this project triages using that capability are now
	// unclassified, and their silence is not a clearance.
	detail := fmt.Sprintf(
		"required analysis capabilit%s %s %s not provided by this installation: "+
			"findings that depend on %s are unevaluated, not cleared",
		plural(len(missing), "y", "ies"),
		strings.Join(missing, ", "),
		plural(len(missing), "is", "are"),
		plural(len(missing), "it", "them"))

	switch mode {
	case UncertaintyFail:
		r.Pass = false
		if r.ExitCode == 0 {
			r.ExitCode = 1
		}
		r.Warnings = append(r.Warnings, "policy.uncertainty=fail: "+detail)

		// Both reasons have to survive. A build failing for two reasons that
		// reports one leaves an operator fixing the finding, seeing the build
		// still red, and having no idea why — so the capability reason is
		// APPENDED to an existing failure rather than skipped, and the summary
		// is only replaced when there was nothing there.
		reason := fmt.Sprintf("unmet capability requirement: %s", strings.Join(missing, ", "))
		switch {
		case r.Summary == "":
			r.Summary = "policy: fail (" + reason + ")"
		case strings.HasPrefix(r.Summary, "policy: fail"):
			r.Summary += "; " + reason
		default:
			r.Summary = "policy: fail (" + reason + "); " + r.Summary
		}
	default:
		// The warning names the flag. §1.5 of the design doc requires a release
		// in which the stricter behaviour is announced by the warning that
		// precedes it, so that switching the default later surprises nobody.
		r.Warnings = append(r.Warnings, detail+
			" — set policy.uncertainty=fail to gate on this, or "+
			"policy.uncertainty=ignore to silence it")
	}
	return r
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
