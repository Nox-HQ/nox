package core

import (
	"os"
	"strings"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// Finding identity belongs to core, not to whichever analyzer emitted the
// finding.
//
// A rule that absorbs a retired ID carries that ID's identity on every finding
// it reports, so baselines, VEX statements and `nox:ignore` comments written
// against the retired ID keep matching. That attachment used to live inside
// rules.Engine.ScanFile, which meant it happened only for findings the ENGINE
// matched. An analyzer that constructs a finding directly could not have it:
//
//   - deps builds CONT-001 and CONT-002 by hand from the parsed Dockerfile
//   - the IaC analyzer evaluates IAC-179/180/182/185/200/501 by parsing, and
//     publishes them through a catalog set the engine never sees
//
// So retiring a rule into any of those would have silently un-waived, in every
// consuming repository, findings an operator had explicitly accepted — and
// nothing would have said so. That is why this pass exists before the
// retirement it enables.
//
// It runs once, over the merged set, against the merged rule set — which
// includes custom rules, so an operator's own rule can retire an ID too.

// attachRetiredIdentities fills in the retired identities of every finding
// whose rule declares a retirement and that does not already carry them.
//
// Findings the engine matched already have theirs, computed while it held the
// line in hand; recomputing would be identical work for the same answer, so
// they are left alone. What matters is that nothing else is left out.
func attachRetiredIdentities(fs *findings.FindingSet, all *rules.RuleSet, artifacts []discovery.Artifact) {
	if fs == nil || all == nil {
		return
	}
	// Only rules that retire something can contribute, and there are a handful.
	retiring := map[string]*rules.Rule{}
	for _, r := range all.Rules() {
		if len(r.Retires) > 0 {
			retiring[r.ID] = r
		}
	}
	if len(retiring) == 0 {
		return
	}

	abs := make(map[string]string, len(artifacts))
	for i := range artifacts {
		abs[artifacts[i].Path] = artifacts[i].AbsPath
	}
	lines := newLineCache(abs)

	items := fs.Findings()
	for i := range items {
		f := &items[i]
		if len(f.RetiredRuleIDs) > 0 {
			continue // The engine already did this one.
		}
		rule, ok := retiring[f.RuleID]
		if !ok {
			continue
		}
		line, ok := lines.at(f.Location.FilePath, f.Location.StartLine)
		if !ok {
			continue
		}
		ids, fps := rules.RetiredIdentities(rule, line, f.Location)
		if len(ids) > 0 {
			fs.SetAliases(i, ids, fps)
		}
	}
}

// lineCache reads a file once and answers for any line in it.
//
// A retirement's pattern is re-run against the finding's own line to reproduce
// the retired rule's exact match text, and therefore its exact fingerprint —
// see rules.RetiredRule. That needs the line, and nothing upstream of here kept
// it, so it is read back. Only files holding a finding from a retiring rule are
// ever opened.
type lineCache struct {
	abs   map[string]string
	files map[string][]string
}

func newLineCache(abs map[string]string) *lineCache {
	return &lineCache{abs: abs, files: map[string][]string{}}
}

func (c *lineCache) at(path string, line int) (string, bool) {
	if line < 1 {
		return "", false
	}
	got, ok := c.files[path]
	if !ok {
		p, known := c.abs[path]
		if !known {
			p = path
		}
		b, err := os.ReadFile(p)
		if err != nil {
			c.files[path] = nil
			return "", false
		}
		got = strings.Split(string(b), "\n")
		c.files[path] = got
	}
	if line > len(got) {
		return "", false
	}
	return got[line-1], true
}
