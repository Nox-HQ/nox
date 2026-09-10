package policy

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/findings"
)

// CIGate is the pass/fail decision a CI job makes about a scan.
//
// It lived in bash. `klarlabs-studio/.github`'s shared go-ci workflow computed
// all four checks below with jq, which meant every consumer that was not that
// workflow either re-implemented them or did without — and the reasoning that
// makes each one right lived in YAML comments where no test could reach it.
//
// The checks are not severity filters. Each exists because a scan can look
// perfectly healthy while having evaluated nothing, and each names a different
// way that happens:
//
//   - no findings.json at all
//   - a required analyzer that did not run
//   - a class of finding this org refuses to regress on, at any severity
//   - a committed baseline that matches nothing
//
// The last is the one with a body count. See DeadBaseline.
type CIGate struct {
	// FindingsWritten is false when the scan produced no findings.json.
	FindingsWritten bool
	// BaselineExists is whether a baseline FILE is committed, which is not the
	// same as whether it matched anything — the distinction the whole
	// dead-baseline check turns on.
	BaselineExists bool
	// Strict gates a repository that has not committed a baseline. Adopting the
	// shared workflow must not break a red build, so an un-baselined repo is
	// report-only unless it opts in.
	Strict bool
	// Degradations are the scan's incomplete checks.
	Degradations []Degradation
	// Findings are every finding the scan reported, suppressed ones included:
	// the gate needs to see what a baseline accepted in order to tell an
	// accepted finding from a baseline that accepted nothing.
	Findings []findings.Finding
}

// Degradation is the gate's view of an incomplete check.
type Degradation struct {
	Kind   string
	Detail string
	Impact string
	// Advisory marks a degradation reporting capability the operator did NOT
	// ask for, as opposed to something they rely on that did not run. Set from
	// degrade.Degradation.Advisory, whose zero value blocks — a degradation
	// nobody classified is one nobody thought about.
	Advisory bool
}

// Blocks reports whether this degradation should fail a build.
//
// A degradation says a check did not complete. Most mean something the
// repository relies on is missing, and those gate. One means the opposite —
// capability that exists and was not asked for — and gating on it punishes a
// repository for what is installed on the machine that scanned it.
//
// The distinction was missing, and the bash this replaced did not have it: the
// shared workflow counted `.meta.degradations | length` and failed on any
// entry, on the stated premise that "repos that have not opted in produce no
// degradations and are unaffected". That premise was false — nox raises a
// Plugin degradation listing installed plugins that are NOT in
// plugins.required, the exact opposite case — so any runner with an undeclared
// plugin failed the gate having asked for nothing.
//
// This read a substring of the impact sentence until nox-core v0.3.1 gave
// Degradation a field for it. That worked and was a seam rather than a design:
// the impact sentence is written for a person, and the first rewording would
// have silently re-broken the gate.
func (d Degradation) Blocks() bool { return !d.Advisory }

// codeSecurityFamilies gate at ANY severity, not just critical/high.
//
// gosec used to cover these and, running under golangci-lint, failed the lint
// job at any severity. It was dropped org-wide on the premise that nox covered
// the same ground. nox does — TLS hardening, world-writable modes, weak
// primitives and predictable randomness, truncation that sizes memory — but
// most of those rules are rated MEDIUM, honestly, because that is what one
// instance is worth in isolation.
//
// Under a critical/high gate they would never fail a build, so porting the
// rules would have restored the coverage on paper and none of the enforcement.
// Severity answers "how bad is one instance"; this list answers "is this a
// class we refuse to regress on". Inflating severities to make the first
// question answer the second would misreport risk everywhere else severity is
// read.
var codeSecurityFamilies = regexp.MustCompile(`^(HARDEN|PERM|CRYPTO|MEMSAFE)-`)

// CIGateResult is what the gate decided and why.
type CIGateResult struct {
	// Pass is false when any check failed.
	Pass bool
	// Errors are the failures, each a sentence naming the fix.
	Errors []string
	// Warnings are reported and do not gate.
	Warnings []string
	// Counts are the numbers a job should print whatever it decided, so a green
	// run says what it evaluated rather than only that it passed.
	NetNewHigh   int
	Baselined    int
	CodeSecurity int
}

// EvaluateCI runs the gate.
//
// Order matters and is preserved from the bash: a missing artifact short-
// circuits, degradations are fatal irrespective of baseline state, and the
// dead-baseline check runs last because it needs the baselined count.
func EvaluateCI(in CIGate) CIGateResult {
	r := CIGateResult{Pass: true}

	if !in.FindingsWritten {
		// Nothing to evaluate. Fatal where the repo has opted into gating,
		// report-only where it has not — adopting a shared workflow must not
		// break a build that was passing.
		if in.BaselineExists || in.Strict {
			return fail(r, "nox wrote no findings.json, so the security gate evaluated "+
				"nothing. Most likely .nox.yaml sets output.format, which overrides the "+
				"workflow's format flag — drop that key, or include json in it.")
		}
		r.Warnings = append(r.Warnings, "nox wrote no findings.json, so the security gate "+
			"evaluated nothing. Report-only (no committed baseline), so not failing the build.")
		return r
	}

	// A scan can COMPLETE while an analyzer never ran. The findings file then
	// looks perfectly healthy: valid JSON, real findings from the analyzers
	// that DID run, and none from the one that did not because nothing looked.
	// Indistinguishable from clean.
	//
	// Fatal irrespective of baseline state, because a required analyzer is
	// opt-in: the repository declared it needs that one. A repository that
	// declared none produces no degradations and is unaffected.
	var blocking []Degradation
	for _, d := range in.Degradations {
		if d.Blocks() {
			blocking = append(blocking, d)
			continue
		}
		r.Warnings = append(r.Warnings, fmt.Sprintf("%s: %s — %s", d.Kind, d.Detail, d.Impact))
	}
	if len(blocking) > 0 {
		lines := []string{"nox ran in a DEGRADED state — an analyzer this repository " +
			"requires did not run, so its findings are absent rather than clean."}
		for _, d := range blocking {
			lines = append(lines, fmt.Sprintf("  %s: %s — %s", d.Kind, d.Detail, d.Impact))
		}
		r = fail(r, strings.Join(lines, "\n"))
	}

	for i := range in.Findings {
		f := &in.Findings[i]
		switch {
		case !f.Status.IsActive():
			if f.Status == findings.StatusBaselined {
				r.Baselined++
			}
		case codeSecurityFamilies.MatchString(f.RuleID):
			r.CodeSecurity++
		}
		if f.Status.IsActive() &&
			(f.Severity == findings.SeverityCritical || f.Severity == findings.SeverityHigh) {
			r.NetNewHigh++
		}
	}

	if r.CodeSecurity > 0 {
		r = fail(r, fmt.Sprintf("%d net-new code-security finding(s). These gate at any "+
			"severity — they are the families gosec used to fail the build on. Remediate, "+
			"or accept explicitly with a baseline entry or a VEX statement.", r.CodeSecurity))
	}

	if r.Baselined == 0 && !in.Strict && in.BaselineExists {
		r = fail(r, DeadBaseline)
		return r
	}
	if r.Baselined == 0 && !in.Strict {
		// No baseline committed: report-only, so adopting the gate never breaks
		// a build that was green.
		if r.NetNewHigh > 0 {
			r.Warnings = append(r.Warnings, fmt.Sprintf("%d net-new critical/high "+
				"finding(s). Report-only: no baseline is committed, so this does not gate. "+
				"Run `nox baseline write .` to start gating.", r.NetNewHigh))
		}
		return r
	}
	if r.NetNewHigh > 0 {
		r = fail(r, fmt.Sprintf("%d net-new critical/high finding(s) above the committed "+
			"baseline.", r.NetNewHigh))
	}
	return r
}

// DeadBaseline is the message for a committed baseline that matched nothing.
//
// A baseline that matches NOTHING is not the same as having no baseline, and
// treating them alike silently deletes the gate.
//
// nox v1.3.0 changed the fingerprint algorithm from
// sha256(rule‖path‖line‖content) to sha256(rule‖normalised_path‖content), so
// every pre-1.3.0 digest stopped matching at once. The repository still looks
// triaged — the file is right there in git — but nothing matches, the
// report-only branch takes over, and the gate exits 0 having evaluated nothing.
// Four repositories sat that way with the security check REQUIRED, one of them
// hiding two net-new critical/high findings. Nobody noticed, because the
// symptom is a green check rather than a red one.
//
// So: an absent baseline stays report-only. Present-but-dead is an error that
// names the fix.
const DeadBaseline = ".nox/baseline.json exists but matched 0 of this scan's findings, " +
	"so the gate evaluated nothing. This is fingerprint drift, not a clean repository. " +
	"Run `nox baseline migrate --prune` to re-fingerprint while preserving each entry's " +
	"triage reason; if nothing migrates, the baselined findings are genuinely gone and " +
	"the file should be rebuilt entry by entry."

func fail(r CIGateResult, msg string) CIGateResult {
	r.Pass = false
	r.Errors = append(r.Errors, msg)
	return r
}
