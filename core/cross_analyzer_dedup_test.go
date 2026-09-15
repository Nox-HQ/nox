package core

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/analyzers/iac"
	"github.com/nox-hq/nox/core/analyzers/secrets"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// One observed security condition must not become several findings because nox
// has several detection paths to it.
//
// This guard used to ask that question only of pairs that CROSSED an analyzer
// boundary, deferring the same-analyzer case to rules_dedup_test.go. That
// deferral was wrong: rules_dedup_test.go lives in core/analyzers/iac and
// compares IaC rules to IaC rules, so the same-analyzer question was asked for
// one analyzer and for nothing else.
//
// What went unasked went wrong. One Shopify shared secret was reported by
// SEC-034 AND SEC-321, one access token by SEC-035 AND SEC-318 — same analyzer,
// identical patterns, invisible here. One bare UUID sitting near the words
// `heroku_api` and `coinbase` was reported as a Heroku key AND a Coinbase key,
// which is worse than noise: at most one of those credentials exists, so an
// operator is told to rotate the wrong one. Twelve duplicate groups and eight
// shape collisions were found by grouping the rule set by pattern, not by any
// test. See docs/design/identical-pattern-audit.md.
//
// So the analyzer boundary is gone from this check. It runs the WHOLE pipeline
// over inputs that each carry one condition and fails when any two rules land
// on the same line, wherever they came from. It cannot prove two rules MEAN the
// same thing; what it can do is refuse to let the question go unasked, which is
// the part that was missing.
//
// The span dedup this relies on lives in core/analyzers/secrets/dedup.go and is
// keyed on a provider PREFIX, so it resolves `sk_live_` and cannot resolve a
// bare UUID. Lifting it to run over the merged finding set, keyed on the
// condition rather than the prefix, is the remaining infrastructure work; this
// test is what will hold the invariant while that happens.

// crossAnalyzerFixtures are inputs carrying ONE condition each. Anything that
// co-fires on a single line here is either a duplicate or an overlap someone
// has to justify in allowedCrossAnalyzerOverlap.
// sixtyFourChars is one 64-character token: the shape Linode and Scaleway both
// claimed before either was bound to its own key name.
const sixtyFourChars = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uVaB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV"

var crossAnalyzerFixtures = map[string]string{
	"Dockerfile":         "FROM ubuntu\nRUN echo hello\n",
	"Dockerfile.pinned":  "FROM ubuntu:22.04\nRUN echo hello\n",
	"docker-compose.yml": "services:\n  web:\n    image: nginx:latest\n",
	"deployment.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n" +
		"spec:\n  template:\n    spec:\n      containers:\n        - name: web\n" +
		"          image: nginx:latest\n",
	"playbook.yml": "- hosts: all\n  tasks:\n    - name: db\n      mysql_user:\n" +
		"        password: hunter2\n",
	// Same-analyzer classes that were invisible until the boundary came out.
	// Each is one credential, and each was reported twice before the merges and
	// bindings in docs/design/identical-pattern-audit.md.
	"shopify.py": "SHOP = \"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\"\n",
	"heroku.py":  "# heroku_api and coinbase\nTOKEN = \"12345678-1234-1234-1234-123456789012\"\n",
	"linode.py":  "# linode_token and scaleway\nTOKEN = \"" + sixtyFourChars + "\"\n",
	"gcp.py":     "KEY = \"AIzaSyD-9tMv2kL3pQ7rX1nB5cW8eR4tY6uI0oP\"\n",
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
	// Same-analyzer pairs, visible only since the analyzer boundary came out of
	// this check. Each names two fixes, which is the bar for an entry here.
	"IAC-200|IAC-225": "set no_log on the task vs. stop hardcoding the password in it",
	"IAC-179|IAC-182": "a Compose service's privileged flag vs. its missing read-only root filesystem",
	"SEC-161|SEC-162": "one value reported as a high-entropy assignment and as a base64 blob: " +
		"two readings of the same bytes, kept apart because the remediation differs — rotate " +
		"the secret, vs. decode the blob and find out whether it holds one",
	// IAC-131 detects the workload and asks for a NetworkPolicy; the others are
	// absence rules on hardening properties of that same workload. Six fixes,
	// one anchor line, because an absence has no line of its own.
	"IAC-131|IAC-137": "missing NetworkPolicy vs. a missing hardening property on the workload",
	"IAC-131|IAC-138": "missing NetworkPolicy vs. a missing hardening property on the workload",
	"IAC-131|IAC-139": "missing NetworkPolicy vs. a missing hardening property on the workload",
	"IAC-131|IAC-140": "missing NetworkPolicy vs. a missing hardening property on the workload",
	"IAC-131|IAC-145": "missing NetworkPolicy vs. a missing hardening property on the workload",
	"IAC-225|SEC-080": "the IaC and secrets views of one hardcoded password",
}

// bothAbsenceRules reports whether two rules both use the absence matcher.
//
// An absence rule answers "this resource does not declare X", and it anchors
// its finding to the RESOURCE, not to the missing property — there is no line
// for something that is not there. So a Dockerfile with no HEALTHCHECK, no USER
// and no LABEL produces three findings at the FROM line, and a Kubernetes
// Deployment missing six hardening properties produces six at its apiVersion.
// Those are six conditions with six fixes that happen to share an anchor, not
// one condition reported six times.
//
// This is an exemption, so it is deliberately narrow and stated as a premise
// rather than assumed: it applies only when BOTH rules use the absence matcher,
// and it does not extend to a pattern rule that merely lands on the same line.
// If the absence matcher ever gains the ability to point at the place a
// property should have been, this exemption should shrink with it.
func bothAbsenceRules(a, b string) bool {
	return isAbsenceRule(a) && isAbsenceRule(b)
}

func isAbsenceRule(id string) bool {
	for _, rs := range []*rules.RuleSet{
		iac.NewAnalyzer().Rules(),
		secrets.NewAnalyzer().Rules(),
	} {
		if r, ok := rs.ByID(id); ok {
			return r.MatcherType == "absence"
		}
	}
	return false
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

func TestOneConditionIsOneFinding(t *testing.T) {
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

				if a > b {
					a, b = b, a
				}
				if bothAbsenceRules(a, b) {
					exercised++
					continue
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
