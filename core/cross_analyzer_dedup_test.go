package core

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// One semantic condition must not be emitted twice by different analyzers.
//
// rules_dedup_test.go in the IaC package compares IaC rules to IaC rules. A
// pair that spans analyzers is outside what it can ask, which is how IAC-002
// and CONT-002 both reported an unpinned Docker base image for as long as they
// did — and how CONT-001 reported it a third time, because "not pinned to a
// digest" is true of everything "uses latest" is true of.
//
// This guard runs the WHOLE pipeline over inputs that each carry one condition,
// and fails when two rules from different analyzers land on the same line. It
// cannot prove two rules mean the same thing; what it can do is refuse to let
// the question go unasked, which is the part that was missing.

// crossAnalyzerFixtures are inputs carrying ONE condition each. Anything that
// co-fires on a single line here is either a duplicate or an overlap someone
// has to justify in allowedCrossAnalyzerOverlap.
var crossAnalyzerFixtures = map[string]string{
	"Dockerfile":         "FROM ubuntu\nRUN echo hello\n",
	"Dockerfile.pinned":  "FROM ubuntu:22.04\nRUN echo hello\n",
	"docker-compose.yml": "services:\n  web:\n    image: nginx:latest\n",
	"deployment.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n" +
		"spec:\n  template:\n    spec:\n      containers:\n        - name: web\n" +
		"          image: nginx:latest\n",
	"playbook.yml": "- hosts: all\n  tasks:\n    - name: db\n      mysql_user:\n" +
		"        password: hunter2\n",
	"secret.yaml": "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\ntype: Opaque\n" +
		"data:\n  password: cXVvYnl0ZQ==\n",
}

// allowedCrossAnalyzerOverlap lists pairs that legitimately land on one line
// because they report genuinely different problems with different fixes. Each
// needs a reason, and the reason has to name both fixes.
var allowedCrossAnalyzerOverlap = map[string]string{
	// A Dockerfile's FROM line is the anchor for the absence rules about the
	// file as a whole, so they share its line number without sharing its
	// subject. Fixing the base image does not add a HEALTHCHECK.
	"CONT-001|IAC-121": "base image pinning vs. a missing HEALTHCHECK instruction",
	"CONT-001|IAC-122": "base image pinning vs. a missing USER instruction",
	"CONT-001|IAC-124": "base image pinning vs. a missing LABEL maintainer",
	"CONT-002|IAC-121": "base image pinning vs. a missing HEALTHCHECK instruction",
	"CONT-002|IAC-122": "base image pinning vs. a missing USER instruction",
	"CONT-002|IAC-124": "base image pinning vs. a missing LABEL maintainer",
	// Two fixes, both needed: stop hardcoding the secret, and stop logging it.
	// (IAC-200 + IAC-225 is deliberately absent: both are IaC rules, so the
	// same-analyzer check skips the pair before it reaches this map, and an
	// entry for it would be an assertion nothing ever consults.)
	"IAC-200|SEC-080": "do not hardcode the password vs. set no_log so it is not printed",
	"IAC-225|SEC-080": "the IaC and secrets views of one hardcoded password",
}

// analyzerOf names the analyzer that owns a rule ID, by prefix.
func analyzerOf(ruleID string) string {
	switch strings.SplitN(ruleID, "-", 2)[0] {
	case "IAC":
		return "iac"
	case "SEC":
		return "secrets"
	case "AI", "MCP", "AGENT", "AGENTFLOW":
		return "ai"
	case "DATA":
		return "data"
	case "CONT", "VULN", "DEP":
		return "deps"
	case "TAINT":
		return "taint"
	case "SLOP":
		return "slop"
	case "VARIANT":
		return "variants"
	default:
		return strings.ToLower(strings.SplitN(ruleID, "-", 2)[0])
	}
}

func TestNoConditionIsReportedByTwoAnalyzers(t *testing.T) {
	dir := t.TempDir()
	for name, body := range crossAnalyzerFixtures {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	res, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	byLine := map[string][]findings.Finding{}
	for _, f := range res.Findings.Findings() {
		k := fmt.Sprintf("%s:%d", f.Location.FilePath, f.Location.StartLine)
		byLine[k] = append(byLine[k], f)
	}

	var problems []string
	var exercised int
	for loc, fs := range byLine {
		for i := range fs {
			for j := i + 1; j < len(fs); j++ {
				a, b := fs[i].RuleID, fs[j].RuleID
				if analyzerOf(a) == analyzerOf(b) {
					continue // rules_dedup_test.go owns the same-analyzer case.
				}
				if a > b {
					a, b = b, a
				}
				if _, ok := allowedCrossAnalyzerOverlap[a+"|"+b]; ok {
					exercised++
					continue
				}
				problems = append(problems, fmt.Sprintf(
					"%s: %s (%s) and %s (%s)", loc, a, analyzerOf(a), b, analyzerOf(b)))
			}
		}
	}
	// A guard whose fixtures produce no cross-analyzer co-firing at all would
	// pass for the wrong reason, and would have passed before IAC-002 was
	// retired too. The allowlist is the evidence that it is actually looking.
	if exercised == 0 {
		t.Fatal("no cross-analyzer pair fired on any fixture, so this guard proves " +
			"nothing. The fixtures no longer reach the rules they were chosen for.")
	}
	if len(problems) == 0 {
		return
	}
	sort.Strings(problems)
	t.Errorf("%d cross-analyzer overlap(s) on one line:\n  %s\n\n"+
		"Two analyzers reporting one condition means an operator fixes it once and sees "+
		"it twice, and a waiver written against one ID does not cover the other. Decide "+
		"which analyzer OWNS the condition, retire the other ID into it with its frozen "+
		"pattern (core.attachRetiredIdentities makes the alias reach a finding an "+
		"analyzer builds by hand), or -- if the two are genuinely different problems with "+
		"different fixes -- add the pair to allowedCrossAnalyzerOverlap with a reason "+
		"naming both fixes.", len(problems), strings.Join(problems, "\n  "))
}
