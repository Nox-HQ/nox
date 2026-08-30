package core

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/adjudicate"
	"github.com/nox-hq/nox/core/replay"
)

func artifactInputs() replay.Inputs {
	// A fixed timestamp, because the artifact is compared byte-for-byte below
	// and a clock read would make determinism untestable by construction.
	return replay.Inputs{
		GeneratedAt: "2026-08-30T00:00:00Z", ToolName: "nox", ToolVersion: "test",
		Target: "../testdata/precision-suite", Offline: true,
	}
}

func scanForArtifact(t *testing.T) *ScanResult {
	t.Helper()
	if testing.Short() {
		t.Skip("end-to-end scan; skipped in -short")
	}
	res, err := RunScanWithOptions("../testdata/precision-suite",
		ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return res
}

// TestTheArtifactCarriesWhatMilestone91Asks. Input identity, capability state,
// claims, provenance, relationships, adjudication result — each checked for
// presence, because an artifact missing one of them replays fine and explains
// nothing.
func TestTheArtifactCarriesWhatMilestone91Asks(t *testing.T) {
	a := scanForArtifact(t).EvidenceArtifact(artifactInputs())

	if a.Meta.SchemaVersion == "" || a.Meta.AdjudicatorVersion == "" {
		t.Errorf("meta does not identify its own format or adjudicator: %+v", a.Meta)
	}
	if a.Meta.FingerprintVersion == 0 {
		t.Error("no fingerprint version; a replay could not match verdicts back to findings")
	}
	if len(a.Capabilities) == 0 {
		t.Error("no capability state: the artifact cannot say what was never asked")
	}
	if len(a.Subjects) == 0 {
		t.Fatal("no claims recorded; every assertion below would be vacuous")
	}
	if len(a.Findings) == 0 {
		t.Fatal("no verdicts recorded")
	}

	var withProvenance int
	for _, s := range a.Subjects {
		for _, c := range s.Claims {
			if c.Provenance.Source != "" {
				withProvenance++
			}
		}
	}
	if withProvenance == 0 {
		t.Error("no claim carries provenance; a claim nobody can attribute is not evidence")
	}
	if len(a.Relations) == 0 {
		t.Error("no relationships recorded, so the artifact cannot show that two " +
			"findings were one condition")
	}

	var explained int
	for _, f := range a.Findings {
		if f.Rationale != "" {
			explained++
		}
	}
	if explained == 0 {
		t.Error("no verdict carries a rationale: the artifact records conclusions " +
			"without the sentence that justified them")
	}
}

// TestTheArtifactIsByteStable. Determinism is the product: an artifact that
// reorders between two identical scans cannot be diffed, and every slice in it
// is built from a Go map.
func TestTheArtifactIsByteStable(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end scan; skipped in -short")
	}
	var first []byte
	for i := 0; i < 3; i++ {
		res, err := RunScanWithOptions("../testdata/precision-suite",
			ScanOptions{Offline: true, RecordReasoning: true})
		if err != nil {
			t.Fatalf("scan %d: %v", i, err)
		}
		data, err := res.EvidenceArtifact(artifactInputs()).Encode()
		if err != nil {
			t.Fatalf("encode %d: %v", i, err)
		}
		if first == nil {
			first = data
			continue
		}
		if !bytes.Equal(first, data) {
			t.Fatalf("scan %d produced a different artifact for the same input; "+
				"map iteration order is reaching the output", i)
		}
	}
}

// TestAVerdictReproducesFromEvidenceAlone is Milestone 9.2.
//
// The replay reads the artifact and nothing else — not the repository, not the
// rules, not the network. That is what makes it answerable at all later: those
// things will have changed, and the question "does this evidence still support
// this verdict?" never depended on them.
func TestAVerdictReproducesFromEvidenceAlone(t *testing.T) {
	a := scanForArtifact(t).EvidenceArtifact(artifactInputs())
	path := filepath.Join(t.TempDir(), "evidence.json")
	if err := a.WriteFile(path); err != nil {
		t.Fatalf("write: %v", err)
	}
	loaded, err := replay.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	res := replay.Replay(loaded)
	if res.VersionChanged {
		t.Fatalf("the artifact was just written by this build and reports a different "+
			"adjudicator: %s vs %s", res.ArtifactVersion, res.ThisVersion)
	}
	if res.Checked == 0 {
		t.Fatal("nothing was replayed; the artifact records verdicts with no evidence " +
			"behind them")
	}
	if !res.Reproduced() {
		t.Errorf("%d verdict(s) did not reproduce and %d had no evidence: %+v",
			len(res.Divergences), len(res.Missing), res.Divergences)
	}
	if !strings.Contains(res.Summary(), "reproduced") {
		t.Errorf("summary does not say what happened: %q", res.Summary())
	}
}

// TestAnEmptyArtifactDoesNotReproducePerfectly. "Nothing to check" must not
// read as "everything checked out" — that is the shape of every false
// all-clear in this codebase, and a replay is exactly where a reader is
// looking for reassurance.
func TestAnEmptyArtifactDoesNotReproducePerfectly(t *testing.T) {
	empty := &replay.Artifact{Meta: replay.Meta{
		SchemaVersion:      replay.SchemaVersion,
		AdjudicatorVersion: adjudicate.Version,
	}}
	res := replay.Replay(empty)
	if res.Reproduced() {
		t.Error("an artifact with no evidence and no verdicts reported a clean reproduction")
	}
	if !strings.Contains(res.Summary(), "nothing was replayed") {
		t.Errorf("summary %q does not say that nothing was checked", res.Summary())
	}
}

// TestAChangedAdjudicatorIsReportedAsAChange. A divergence under a different
// adjudicator version is an upgrade, not a regression, and a replay that
// cannot tell them apart is an alarm nobody will trust twice.
func TestAChangedAdjudicatorIsReportedAsAChange(t *testing.T) {
	a := scanForArtifact(t).EvidenceArtifact(artifactInputs())
	a.Meta.AdjudicatorVersion = "0-from-an-older-build"

	res := replay.Replay(a)
	if !res.VersionChanged {
		t.Fatal("an artifact from a different adjudicator was replayed as if comparable")
	}
	if !strings.Contains(res.Summary(), "change in adjudication rather than a defect") {
		t.Errorf("summary %q reads a version change as a failure", res.Summary())
	}
}

// TestAnUnknownSchemaIsRefused. A reader that half-understands an evidence file
// produces a confident answer from an unknown subset of the evidence, which
// looks exactly like a correct one.
func TestAnUnknownSchemaIsRefused(t *testing.T) {
	a := &replay.Artifact{Meta: replay.Meta{SchemaVersion: "99.0.0"}}
	path := filepath.Join(t.TempDir(), "future.json")
	if err := a.WriteFile(path); err != nil {
		t.Fatal(err)
	}
	if _, err := replay.Load(path); err == nil {
		t.Error("an artifact from an unrecognised schema version loaded without complaint")
	}
}

// TestClaimOrderWithinASubjectIsLoadBearing pins a property that looks like
// untidiness and is not.
//
// The kernel breaks strength ties by taking the EARLIEST claim, deliberately —
// its own test says "the earlier claim wins so repeated evaluation is stable".
// So among claims of equal strength, the one that carried a verdict, and
// therefore the rationale an operator read, is a function of the order they
// were recorded in.
//
// Sorting them inside the artifact is the obvious tidy-up and it silently
// rewrites explanations. Measured when this package was written: sorting claims
// by kind, source and statement changed the rationale on 10 of 37 findings,
// every one a tie between heuristics. The labels all still reproduced. Only the
// sentence moved, which is the half a person actually reads.
func TestClaimOrderWithinASubjectIsLoadBearing(t *testing.T) {
	a := scanForArtifact(t).EvidenceArtifact(artifactInputs())

	// Find a subject whose strongest claim is tied, which is the only case
	// where order can matter.
	var reordered bool
	for i := range a.Subjects {
		claims := a.Subjects[i].Claims
		if len(claims) < 2 {
			continue
		}
		top := claims[0].Kind.Strength()
		tied := 0
		for _, c := range claims {
			if c.Kind.Strength() == top {
				tied++
			}
		}
		if tied < 2 {
			continue
		}
		// Reverse the claims and see whether the verdict's explanation moves.
		a.Subjects[i].Claims = reverseClaims(claims)
		reordered = true
		break
	}
	if !reordered {
		t.Skip("no subject in this corpus has tied claims; nothing to demonstrate")
	}

	res := replay.Replay(a)
	if res.Reproduced() {
		t.Error("reordering tied claims changed nothing, so either the kernel no " +
			"longer breaks ties by position or this corpus stopped exercising it. " +
			"Either way the artifact may now sort claims — check the kernel first, " +
			"because the alternative is that this test stopped testing anything")
	}
	var rationaleMoved bool
	for _, d := range res.Divergences {
		if d.Field == "rationale" {
			rationaleMoved = true
		}
	}
	if !rationaleMoved {
		t.Errorf("reordering tied claims moved something other than the rationale: %+v",
			res.Divergences)
	}
}

func reverseClaims(in []evidence.Claim) []evidence.Claim {
	out := make([]evidence.Claim, len(in))
	for i := range in {
		out[len(in)-1-i] = in[i]
	}
	return out
}
