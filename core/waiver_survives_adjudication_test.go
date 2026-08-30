package core

import (
	"testing"
	"time"

	"github.com/nox-hq/nox/core/baseline"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/suppress"
	"github.com/nox-hq/nox/core/vex"
)

// Track C4: the waivers written against today's findings must still match the
// findings that come out of adjudication.
//
// Baselines, VEX statements and nox:ignore comments live in the repositories
// that consume nox, not in this one. A change here that moves a fingerprint
// does not fail a test in this repository — it turns somebody else's gate red
// on a commit that touched nothing, and the only diagnosis available to them is
// "nox upgraded". These tests are this repository's half of that contract.

// c4Scan runs one real scan over the committed precision suite.
//
// Both halves of every test below come from RunScanWithOptions rather than from
// a helper that simulates a scan. An earlier draft mutated findings in place
// and recomputed their fingerprints through FindingSet.Add; it reported 15 of
// 37 baseline entries broken by a flip that touched nothing but Exploitability
// and Metadata. The flip was innocent — the helper was wrong, and it was wrong
// in a way that taught something (see TestFingerprintProducersAreNotUniform).
// Going through the real pipeline is what makes these assertions mean the thing
// they claim to mean.
func c4Scan(t *testing.T, adjudicate bool) []findings.Finding {
	t.Helper()
	if testing.Short() {
		t.Skip("end-to-end scan; skipped in -short")
	}
	res, err := RunScanWithOptions("../testdata/precision-suite",
		ScanOptions{Offline: true, RecordReasoning: adjudicate})
	if err != nil {
		t.Fatalf("scan (adjudicate=%v): %v", adjudicate, err)
	}
	fs := res.Findings.Findings()
	if len(fs) == 0 {
		t.Fatal("the corpus produced no findings; every assertion below would be vacuous")
	}
	return fs
}

// waiverCorpus is one of each waiver kind, written against the findings a scan
// produces today — the state a consuming repository is in before it upgrades.
type waiverCorpus struct {
	base         *baseline.Baseline
	vexDoc       *vex.Document
	pinnedVEX    *vex.Document
	suppressions []suppress.Suppression
}

func waiversFor(t *testing.T, fs []findings.Finding) waiverCorpus {
	t.Helper()
	c := waiverCorpus{base: &baseline.Baseline{}, vexDoc: &vex.Document{}, pinnedVEX: &vex.Document{}}
	now := time.Now()
	for _, f := range fs {
		c.base.Add(&baseline.Entry{
			Fingerprint: f.Fingerprint,
			RuleID:      f.RuleID,
			FilePath:    f.Location.FilePath,
			Severity:    f.Severity,
			Reason:      "accepted before the upgrade",
			CreatedAt:   now,
		})
		c.vexDoc.Statements = append(c.vexDoc.Statements, vex.Statement{
			VulnerabilityID: f.RuleID,
			Status:          vex.StatusNotAffected,
			Justification:   "vulnerable_code_not_in_execute_path",
			NoxFingerprint:  f.Fingerprint,
		})
		// The same statement with a vulnerability ID no live rule answers to,
		// so only the fingerprint pin can match it. ApplyVEX falls back to the
		// rule ID when the pin misses, which is a good property and a bad test:
		// it hides a broken pin completely. This document isolates the pin.
		c.pinnedVEX.Statements = append(c.pinnedVEX.Statements, vex.Statement{
			VulnerabilityID: "CVE-2026-00000",
			Status:          vex.StatusNotAffected,
			Justification:   "vulnerable_code_not_in_execute_path",
			NoxFingerprint:  f.Fingerprint,
		})
		c.suppressions = append(c.suppressions, suppress.Suppression{
			RuleIDs:  []string{f.RuleID},
			FilePath: f.Location.FilePath,
			Line:     f.Location.StartLine,
			Reason:   "accepted before the upgrade",
		})
	}
	return c
}

type waiverLoss struct{ baseline, vex, pinnedVEX, ignore int }

func (l waiverLoss) any() bool {
	return l.baseline+l.vex+l.pinnedVEX+l.ignore != 0
}

// unwaived counts the findings each waiver kind no longer covers.
func (c waiverCorpus) unwaived(t *testing.T, fs []findings.Finding) waiverLoss {
	t.Helper()
	var l waiverLoss

	applied := func(doc *vex.Document) []findings.Finding {
		set := findings.NewFindingSet()
		for _, f := range fs {
			f.Status = ""
			set.Add(f)
		}
		vex.ApplyVEX(set, doc)
		return set.Findings()
	}
	afterVEX, afterPinned := applied(c.vexDoc), applied(c.pinnedVEX)

	for i := range fs {
		f := fs[i]
		if c.base.Match(&f) == nil {
			l.baseline++
		}
		if afterVEX[i].Status.IsActive() {
			l.vex++
		}
		if afterPinned[i].Status.IsActive() {
			l.pinnedVEX++
		}
		covered := false
		for _, s := range c.suppressions {
			if s.FilePath == f.Location.FilePath && suppressionCovers(s, &f) {
				covered = true
				break
			}
		}
		if !covered {
			l.ignore++
		}
	}
	return l
}

// TestWaiversSurviveAdjudication is the C4 gate on C5, run end to end: waivers
// written against a scan that does not adjudicate still match every finding of
// a scan that does.
//
// Today adjudication is shadow-only, so this passes by construction — which is
// exactly why it is worth committing now rather than alongside C5. It is the
// assertion that turns red the first time adjudication reaches a field a
// fingerprint depends on, and it will already be in the tree, already green,
// already trusted, when that change is written.
func TestWaiversSurviveAdjudication(t *testing.T) {
	before := c4Scan(t, false)
	waivers := waiversFor(t, before)

	// An assertion that nothing was lost means nothing unless everything was
	// covered to start with.
	if l := waivers.unwaived(t, before); l.any() {
		t.Fatalf("the waiver corpus does not cover the findings it was built from "+
			"(baseline %d, vex %d, pinned vex %d, ignore %d); the survival check below "+
			"would pass for the wrong reason", l.baseline, l.vex, l.pinnedVEX, l.ignore)
	}

	after := c4Scan(t, true)
	if len(after) != len(before) {
		t.Fatalf("adjudication changed the finding count: %d -> %d", len(before), len(after))
	}
	l := waivers.unwaived(t, after)
	if l.baseline != 0 {
		t.Errorf("%d of %d baseline entries stopped matching after adjudication; every one "+
			"is a finding an operator already accepted, resurfacing as new", l.baseline, len(before))
	}
	if l.vex != 0 || l.pinnedVEX != 0 {
		t.Errorf("%d of %d VEX statements stopped applying after adjudication (%d of them "+
			"fingerprint-pinned)", l.vex, len(before), l.pinnedVEX)
	}
	if l.ignore != 0 {
		t.Errorf("%d of %d nox:ignore comments stopped covering their finding after adjudication",
			l.ignore, len(before))
	}
}

// TestExplainingInTheMessageUnwaives measures the mistake instead of warning
// about it.
//
// Message is a fingerprint ingredient on the FindingSet.Add path (see
// findings.TestFingerprintIngredientsAreClosed). C5 makes findings explain
// themselves, and the first shape anyone reaches for is a longer message — so
// this appends one clause to every message, recomputes, and counts what stops
// matching.
//
// It asserts the damage rather than against it. If a later change makes
// messages safe to extend, this test fails, and the fix is to update the
// ingredient table and the migration note together with it — not to quietly
// delete the number.
func TestExplainingInTheMessageUnwaives(t *testing.T) {
	before := c4Scan(t, false)
	waivers := waiversFor(t, before)

	// Only the findings whose fingerprint actually hashes Message can move.
	// The rest are the rule engine's, which hashes the matched text instead.
	explained := findings.NewFindingSet()
	var atRisk int
	for _, f := range before {
		if findings.ComputeFingerprint(f.RuleID, f.Location, f.Message) == f.Fingerprint {
			atRisk++
			f.Message += " (POTENTIAL: no attack path was constructed)"
			f.Fingerprint = ""
			f.ID = ""
		}
		explained.Add(f)
	}
	if atRisk == 0 {
		t.Fatal("no finding in the corpus hashes its message; this test measures nothing")
	}

	l := waivers.unwaived(t, explained.Findings())
	if l.baseline != atRisk || l.pinnedVEX != atRisk {
		t.Errorf("extending the message broke %d baseline entries and %d fingerprint-pinned "+
			"VEX statements, of %d findings that hash their message. If fingerprints have "+
			"stopped depending on the message, update fingerprintIngredients and "+
			"docs/migration-fingerprint-v2.md rather than this number",
			l.baseline, l.pinnedVEX, atRisk)
	}
	// Two waiver kinds survive, and the asymmetry is the operator's experience:
	// nox:ignore names a rule ID and a line, and an unpinned VEX statement falls
	// back to the rule ID, so roughly half their waivers keep working. That
	// reads as a partial outage rather than as a format change, which is why
	// this must never ship unannounced.
	if l.ignore != 0 {
		t.Errorf("%d nox:ignore comments stopped matching; they key on rule ID and line, "+
			"so the message cannot be what broke them", l.ignore)
	}
	if l.vex != 0 {
		t.Errorf("%d unpinned VEX statements stopped matching; they fall back to the rule ID, "+
			"so the message cannot be what broke them", l.vex)
	}
	t.Logf("blast radius of writing the verdict into Message: %d/%d baseline, %d/%d pinned VEX, "+
		"%d unpinned VEX, %d nox:ignore", l.baseline, len(before), l.pinnedVEX, atRisk, l.vex, l.ignore)
}

// TestFingerprintProducersAreNotUniform records the fact that surfaced while
// building this track, because it changes what "adjudication must not touch X"
// means.
//
// Two code paths compute fingerprints from different ingredients.
// FindingSet.Add hashes the finding's Message; the rule engine hashes the text
// its pattern matched (core/rules/engine.go) and never consults the message at
// all. Both emit the same Finding type through the same reports, so nothing
// downstream can tell which contract a given fingerprint was written under.
//
// The consequence is specific: "an adjudicated finding must not extend its
// message" is a real constraint for the analyzers on the first path and no
// constraint at all for rules on the second — while "must not change the
// matched text" is the reverse. A single sentence in a design document cannot
// be true for both, so the split is pinned here where a reader will find it.
//
// The assertion is deliberately that BOTH paths are represented, not that the
// counts hold. Counts move whenever a rule is added to the corpus; the split
// existing is the thing that must not be forgotten.
func TestFingerprintProducersAreNotUniform(t *testing.T) {
	fs := c4Scan(t, false)

	var hashesMessage, hashesSomethingElse int
	for _, f := range fs {
		if findings.ComputeFingerprint(f.RuleID, f.Location, f.Message) == f.Fingerprint {
			hashesMessage++
		} else {
			hashesSomethingElse++
		}
	}
	if hashesMessage == 0 || hashesSomethingElse == 0 {
		t.Errorf("the corpus exercises only one fingerprint producer (message-hashing %d, "+
			"other %d). C4's constraints differ per producer, so a corpus that covers one "+
			"of them cannot tell you whether the other still holds", hashesMessage, hashesSomethingElse)
	}
	t.Logf("fingerprint producers in the corpus: %d hash Message, %d hash the matched text",
		hashesMessage, hashesSomethingElse)
}
