package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/attack"
	"github.com/nox-hq/nox/core/intel"
)

// Contributing attack evidence.
//
// `nox attack run|replay --contribute --candidate <fp>` sends what a run in YOUR
// CI established to NOX Intelligence as reporter-scoped evidence. It is the
// owner-approved route for execution evidence: the service executes nothing, and
// it never trusts a report beyond the reporter that sent it (see
// docs/intelligence.md). It is consent-gated like scan contributions, with its
// own terms because it is attributed to your organisation, and it redacts here,
// in the binary, before anything leaves: the wire type is nox-core's
// evidence.RunReport, an allowlist with no target, route, payload or response.

// contributeFlags are the flags `attack run` and `attack replay` share.
type contributeFlags struct {
	contribute *bool
	candidate  *string
	endpoint   *string
	accept     *string
}

func addContributeFlags(fs *flag.FlagSet) contributeFlags {
	return contributeFlags{
		contribute: fs.Bool("contribute", false, "send this run's allowlisted evidence to NOX Intelligence (needs NOX_INTEL_TOKEN, --candidate and accepted attack terms)"),
		candidate:  fs.String("candidate", "", "fingerprint of the intelligence candidate this run exercised (64 hex); your statement, sent as that"),
		endpoint:   fs.String("endpoint", intelEndpointDefault(), "intelligence service base URL"),
		accept:     fs.String("accept-attack-terms", "", "accept the attack-evidence terms non-interactively; must name "+intel.AttackTermsVersion),
	}
}

// preflight refuses before any attack fires. A run that cannot be contributed
// should not have been run on the promise that it would be.
func (f contributeFlags) preflight(errw io.Writer) (token string, code int) {
	if !*f.contribute {
		return "", 0
	}
	if !intel.ValidCandidateFingerprint(*f.candidate) {
		_, _ = fmt.Fprintln(errw, "error: --contribute needs --candidate <64 hex>: nox cannot tell which intelligence candidate a run is about, so you say it")
		return "", 2
	}
	token = strings.TrimSpace(os.Getenv("NOX_INTEL_TOKEN"))
	if token == "" {
		_, _ = fmt.Fprintln(errw, "error: --contribute needs an organisation token in NOX_INTEL_TOKEN: attack evidence is only accepted from an attested reporter")
		return "", 2
	}
	sp := saltPathFor("")
	if *f.accept != "" {
		if *f.accept != intel.AttackTermsVersion {
			_, _ = fmt.Fprintf(errw, "error: --accept-attack-terms=%s, but the current terms are %s\n", *f.accept, intel.AttackTermsVersion)
			return "", 2
		}
		if err := intel.RecordAttackConsent(sp, time.Now().UTC().Format(time.RFC3339)); err != nil {
			_, _ = fmt.Fprintf(errw, "error: %v\n", err)
			return "", 2
		}
	}
	if status, _ := intel.LoadAttackConsent(sp); status != intel.ConsentGranted {
		_, _ = fmt.Fprintln(errw, "error: attack-evidence terms are not accepted on this machine (or changed). Read them with `nox intel consent attack show`,")
		_, _ = fmt.Fprintln(errw, "accept with `nox intel consent attack accept`. Nothing was run and nothing was sent.")
		return "", 2
	}
	return token, 0
}

// runReportsFromTraces turns executed traces into reports and says why it left
// any out. A trace nothing exercised is never sent: "the target was never
// reached" must not become a stored "prevented".
func runReportsFromTraces(traces []attack.Trace, candidate, profile, generatedAt, toolVersion string) ([]evidence.RunReport, []string) {
	var out []evidence.RunReport
	var skipped []string
	for i := range traces {
		tr := &traces[i]
		switch {
		case !tr.Outcome.Executed:
			skipped = append(skipped, fmt.Sprintf("%s: not executed (%s), nothing to report", tr.ID, tr.Exploitability))
			continue
		case !tr.Outcome.ControlSound:
			skipped = append(skipped, fmt.Sprintf("%s: the benign control tripped, so the environment cannot support a verdict", tr.ID))
			continue
		case tr.Outcome.TargetErrors > 0:
			skipped = append(skipped, fmt.Sprintf("%s: %d attempt(s) never reached the target; an unexercised run is not reported", tr.ID, tr.Outcome.TargetErrors))
			continue
		}
		digest, err := traceDigest(tr)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", tr.ID, err))
			continue
		}
		r := evidence.RunReport{
			SchemaVersion:  evidence.RunReportSchema,
			Fingerprint:    candidate,
			Exploitability: tr.Exploitability,
			Kind:           evidence.KindHeuristic,
			ControlSound:   tr.Outcome.ControlSound,
			Samples:        tr.ReproductionSamples,
			Hits:           tr.ReproductionHits,
			Profile:        profile,
			TraceDigest:    digest,
			Tool:           "nox",
			Version:        reportVersion(toolVersion),
			ObservedAt:     generatedAt,
		}
		// The reporter-side kind comes from the oracle that decided the run, and
		// CONFIRMED is only ever claimed with a deterministic one; the shared
		// type refuses anything else.
		if tr.Exploitability == evidence.Confirmed && tr.Evidence != nil && tr.Evidence.OracleKind != attack.OracleSemantic {
			r.Kind = evidence.KindDynamicExploit
			r.Deterministic = true
			r.Reproduced = tr.Evidence.Reproduced
		}
		if tr.Evidence != nil {
			r.Samples, r.Hits = tr.Evidence.Samples, tr.Evidence.Hits
		}
		if err := r.Validate(); err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", tr.ID, err))
			continue
		}
		out = append(out, r)
	}
	return out, skipped
}

// traceDigest is the SHA-256 of the trace as recorded: one-way, so it names the
// run for its owner and reveals nothing of it to anyone else.
func traceDigest(tr *attack.Trace) (string, error) {
	raw, err := json.Marshal(tr)
	if err != nil {
		return "", fmt.Errorf("cannot digest trace: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// reportVersion keeps only a version the shared type accepts.
func reportVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "dev"
	}
	return v
}

// contribute sends the reports and prints what happened. It never changes the
// exit code of the attack: a contribution is a courtesy to the network, and a
// CI gate that failed because an upload did would make opting in hostile.
func (f contributeFlags) contribute_(token string, traces []attack.Trace, profile, generatedAt string, out, errw io.Writer) {
	reports, skipped := runReportsFromTraces(traces, *f.candidate, profile, generatedAt, version)
	for _, s := range skipped {
		_, _ = fmt.Fprintf(out, "[contribute] skipped %s\n", s)
	}
	if len(reports) == 0 {
		_, _ = fmt.Fprintln(out, "[contribute] no executed run to report; nothing was sent")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cl := intel.NewClient(*f.endpoint, nil).WithToken(token)
	sent := 0
	for _, r := range reports {
		rc, err := cl.SubmitRun(ctx, r)
		if err != nil {
			_, _ = fmt.Fprintf(errw, "[contribute] not accepted (%s %s): %v\n", r.Exploitability, r.TraceDigest[:12], err)
			continue
		}
		sent++
		_, _ = fmt.Fprintf(out, "[contribute] accepted %s %s: scope=%s, attested reporters with a reproduced violation: %d\n",
			r.Exploitability, r.TraceDigest[:12], rc.Scope, rc.AttackReporter)
	}
	_, _ = fmt.Fprintf(out, "[contribute] %d of %d run(s) sent. Reporter-scoped: it cannot change the candidate's confidence for anyone else.\n", sent, len(reports))
}
