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

// CapabilityRun is the run half of the same decision: what a capability
// actually established during THIS scan.
//
// It exists because CapabilityGate alone cannot keep the promise this file
// makes. Provided answers "is anything on this installation able to establish
// c" — a fact about the binary, true before the scan starts and unchanged by
// anything that happens during it. A project that declares it depends on
// reachability is not asking about the binary.
type CapabilityRun interface {
	// Answered reports how many subjects c concluded about, and how many it was
	// asked about and could not determine. A nil implementation means the
	// caller has no run view, and the gate falls back to the installation
	// question alone.
	Answered(c capability.AnalysisCapability) (answered, inconclusive int)
}

// EvaluateCapabilities checks a project's declared capability requirements
// against what the installation provides AND what this scan established, and
// folds the outcome into an existing policy Result.
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
//
// # Why the installation question is not enough
//
// This used to ask Provided and stop, and that did not keep the promise above.
// Measured: a scan of a Go module whose advisory source was unreachable
// produced zero findings, recorded a degradation saying in plain words that it
// "cannot confirm the absence of known CVEs", and returned pass=true exit=0
// under uncertainty=fail with require_capabilities: [reachability]. Every
// capability was still "provided" — core/analyzers/deps is compiled into every
// build — and none of them had established anything.
//
// That is the strictest configuration this gate offers returning a clean bill
// on a scan that answered nothing, which is the failure the whole programme
// exists to prevent, in the one place built to prevent it.
//
// So a requirement is satisfied only when the capability is provided AND this
// scan actually reached a conclusion with it. Three outcomes, deliberately
// worded apart, because they need different actions from the reader:
// unsupported means install a plugin, inconclusive means the analysis ran and
// could not tell, and unexercised means nothing in this scan put the question.
func EvaluateCapabilities(cfg Config, gate CapabilityGate, run CapabilityRun, r *Result) *Result {
	if r == nil {
		r = &Result{Pass: true, ExitCode: 0}
	}
	mode := cfg.Uncertainty.Effective()
	if mode == UncertaintyIgnore || len(cfg.RequireCapabilities) == 0 {
		return r
	}

	var unsupported, inconclusive, unexercised []string
	for _, name := range cfg.RequireCapabilities {
		c := capability.AnalysisCapability(name)
		if gate == nil || !gate.Provided(c) {
			unsupported = append(unsupported, name)
			continue
		}
		if run == nil {
			// No run view. Falling back to the installation answer is the old
			// behaviour and is permissive, so it must never be reached silently
			// from the scan pipeline — TestScanAlwaysSuppliesARunView holds that.
			continue
		}
		answered, undetermined := run.Answered(c)
		switch {
		case answered > 0:
			continue
		case undetermined > 0:
			inconclusive = append(inconclusive, name)
		default:
			unexercised = append(unexercised, name)
		}
	}
	missing := append(append(append([]string(nil), unsupported...), inconclusive...), unexercised...)
	if len(missing) == 0 {
		return r
	}
	sort.Strings(missing)
	sort.Strings(unsupported)
	sort.Strings(inconclusive)
	sort.Strings(unexercised)

	// The wording carries the whole point. An operator who reads this as "nox
	// is missing a feature" has drawn the wrong conclusion; what it means is
	// that findings this project triages using that capability are now
	// unclassified, and their silence is not a clearance.
	var parts []string
	if len(unsupported) > 0 {
		parts = append(parts, fmt.Sprintf(
			"%s: not provided by this installation", strings.Join(unsupported, ", ")))
	}
	if len(inconclusive) > 0 {
		parts = append(parts, fmt.Sprintf(
			"%s: ran but could not determine anything", strings.Join(inconclusive, ", ")))
	}
	if len(unexercised) > 0 {
		parts = append(parts, fmt.Sprintf(
			"%s: provided, but nothing in this scan put the question", strings.Join(unexercised, ", ")))
	}
	detail := fmt.Sprintf(
		"required analysis capabilit%s not satisfied — %s. Findings that depend on %s "+
			"are unevaluated, not cleared",
		plural(len(missing), "y", "ies"),
		strings.Join(parts, "; "),
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
