package iac

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// The conditions that used to be reported twice, each checked from the outside:
// one finding, from the rule that kept the ID, still covering everything the
// retired rule covered.

func scanIaC(t *testing.T, path, content string) []findings.Finding {
	t.Helper()
	got, err := NewAnalyzer().ScanFile(path, []byte(content))
	if err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	return got
}

func rulesFiring(fs []findings.Finding) map[string]int {
	out := map[string]int{}
	for i := range fs {
		out[fs[i].RuleID]++
	}
	return out
}

// TestRetired_OneFindingPerCondition walks the retirements: the condition is
// reported exactly once, by the surviving ID, and the retired ID is gone.
func TestRetired_OneFindingPerCondition(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		content  string
		survivor string
		retired  string
	}{
		{"hostPID", "pod.yaml", "spec:\n  hostPID: true\n", "IAC-026", "IAC-291"},
		{"hostIPC", "pod.yaml", "spec:\n  hostIPC: true\n", "IAC-027", "IAC-292"},
		{"automount token", "pod.yaml", "spec:\n  automountServiceAccountToken: true\n", "IAC-030", "IAC-287"},
		{"privileged", "pod.yaml", "        privileged: true\n", "IAC-007", "IAC-237"},
		{"set-output", "ci.yml", "      - run: echo \"::set-output name=v::1\"\n", "IAC-017", "IAC-312"},
		{"continue-on-error", "ci.yml", "      - continue-on-error: true\n", "IAC-018", "IAC-310"},
		{"publicly accessible", "rds.tf", "  publicly_accessible = true\n", "IAC-036", "IAC-283"},
		{"azure http", "storage.tf", "  enable_https_traffic_only = false\n", "IAC-042", "IAC-321"},
		{"secure boot", "vm.tf", "  enable_secure_boot = false\n", "IAC-111", "IAC-333"},
		{"require ssl", "sql.tf", "  require_ssl = false\n", "IAC-116", "IAC-337"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			firing := rulesFiring(scanIaC(t, tc.path, tc.content))
			if got := firing[tc.survivor]; got != 1 {
				t.Errorf("%s fired %d times, want exactly 1 — the condition must still be reported",
					tc.survivor, got)
			}
			if got := firing[tc.retired]; got != 0 {
				t.Errorf("%s is retired but fired %d times", tc.retired, got)
			}
		})
	}
}

// TestRetired_IAC065PrivilegedBranchMovedToIAC007 checks the one partial
// retirement from both ends: the branch that moved is reported by IAC-007
// (including the quoted form and *.template files, which only IAC-065 used to
// reach), and the branch that stayed is still reported by IAC-065.
func TestRetired_IAC065PrivilegedBranchMovedToIAC007(t *testing.T) {
	t.Run("quoted privileged in a CloudFormation template", func(t *testing.T) {
		content := "Resources:\n  Task:\n    Properties:\n      ContainerDefinitions:\n        - Privileged: \"true\"\n"
		fs := scanIaC(t, "ecs.template", content)
		firing := rulesFiring(fs)
		if firing["IAC-007"] != 1 {
			t.Errorf("IAC-007 fired %d times on a *.template with Privileged: \"true\"; "+
				"absorbing IAC-065 must not lose the quoted form or the file type", firing["IAC-007"])
		}
		if firing["IAC-065"] != 0 {
			t.Errorf("IAC-065 still reports privileged (%d findings) — the branch was supposed to move",
				firing["IAC-065"])
		}
		for i := range fs {
			if fs[i].RuleID != "IAC-007" {
				continue
			}
			if !fs[i].MatchesRuleID("IAC-065") {
				t.Errorf("the IAC-007 finding does not answer to IAC-065 (%v); waivers written "+
					"against IAC-065 for this line stop applying", fs[i].RetiredRuleIDs)
			}
		}
	})

	t.Run("root user stays with IAC-065", func(t *testing.T) {
		content := "Resources:\n  Task:\n    Properties:\n      ContainerDefinitions:\n        - User: root\n"
		firing := rulesFiring(scanIaC(t, "ecs.template", content))
		if firing["IAC-065"] != 1 {
			t.Errorf("IAC-065 fired %d times on `User: root`, want 1 — narrowing it must not "+
				"drop the branch nothing else covers", firing["IAC-065"])
		}
	})
}

// TestNarrowed_GenericPatternNoLongerSwallowsTheSpecificOne covers the two pairs
// that were not duplicates but a generic pattern reaching into a specific one's
// territory. Both rules survive; each keeps its own ground.
func TestNarrowed_GenericPatternNoLongerSwallowsTheSpecificOne(t *testing.T) {
	t.Run("storage_encrypted belongs to IAC-037", func(t *testing.T) {
		firing := rulesFiring(scanIaC(t, "rds.tf", "  storage_encrypted = false\n"))
		if firing["IAC-037"] != 1 {
			t.Errorf("IAC-037 fired %d times, want 1", firing["IAC-037"])
		}
		if firing["IAC-005"] != 0 {
			t.Errorf("the generic IAC-005 still fires on storage_encrypted (%d findings)",
				firing["IAC-005"])
		}
	})

	t.Run("a bare encrypted attribute is still IAC-005", func(t *testing.T) {
		firing := rulesFiring(scanIaC(t, "ebs.tf", "  encrypted = false\n"))
		if firing["IAC-005"] != 1 {
			t.Errorf("IAC-005 fired %d times on `encrypted = false`, want 1 — narrowing it "+
				"must not cost the attributes it is the only rule for", firing["IAC-005"])
		}
	})

	t.Run("minReplicas belongs to IAC-399", func(t *testing.T) {
		firing := rulesFiring(scanIaC(t, "hpa.yaml", "spec:\n  minReplicas: 1\n"))
		if firing["IAC-399"] != 1 {
			t.Errorf("IAC-399 fired %d times, want 1", firing["IAC-399"])
		}
		if firing["IAC-141"] != 0 {
			t.Errorf("the Deployment rule IAC-141 still fires on minReplicas (%d findings)",
				firing["IAC-141"])
		}
	})

	t.Run("a Deployment replica count is still IAC-141", func(t *testing.T) {
		firing := rulesFiring(scanIaC(t, "deploy.yaml", "spec:\n  replicas: 1\n"))
		if firing["IAC-141"] != 1 {
			t.Errorf("IAC-141 fired %d times on `replicas: 1`, want 1", firing["IAC-141"])
		}
	})
}

// TestNarrowed_FingerprintsOfSurvivingMatchesAreUnchanged pins the reason both
// narrowings use `\b` rather than a leading-whitespace anchor: the matched text
// is what the fingerprint hashes, so widening the match would invalidate every
// baseline entry for the rule while "only" tightening its scope.
func TestNarrowed_FingerprintsOfSurvivingMatchesAreUnchanged(t *testing.T) {
	cases := []struct {
		name, path, content, ruleID, patternBefore string
	}{
		{
			name: "IAC-005 on a bare encrypted attribute", path: "ebs.tf",
			content: "  encrypted = false\n", ruleID: "IAC-005",
			patternBefore: `(?i)encrypt\w*\s*=\s*(false|"false")`,
		},
		{
			name: "IAC-141 on a Deployment replica count", path: "deploy.yaml",
			content: "spec:\n  replicas: 1\n", ruleID: "IAC-141",
			patternBefore: `(?im)replicas\s*:\s*1\s*$`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := scanWithPattern(t, tc.ruleID, tc.patternBefore, tc.path, tc.content)

			var found bool
			for _, f := range scanIaC(t, tc.path, tc.content) {
				if f.RuleID != tc.ruleID {
					continue
				}
				found = true
				if f.Fingerprint != before.Fingerprint {
					t.Errorf("%s fingerprint changed (%s -> %s): the narrowed pattern matches "+
						"different text, so every baseline entry for this rule stops matching",
						tc.ruleID, before.Fingerprint[:12], f.Fingerprint[:12])
				}
			}
			if !found {
				t.Errorf("%s did not fire on %q at all", tc.ruleID, tc.content)
			}
		})
	}
}

// scanWithPattern runs one rule, defined by ID and pattern alone, over content —
// used to reproduce what a rule produced BEFORE its pattern was narrowed.
func scanWithPattern(t *testing.T, ruleID, pattern, path, content string) findings.Finding {
	t.Helper()
	rs := rules.NewRuleSet()
	rs.Add(&rules.Rule{
		ID: ruleID, Version: "1.0", Description: "before",
		Severity: findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
		MatcherType: "regex", Pattern: pattern,
	})
	got, err := rules.NewEngine(rs).ScanFile(path, []byte(content))
	if err != nil {
		t.Fatalf("scan with the pre-change pattern: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("the pre-change %s produced %d findings, want 1", ruleID, len(got))
	}
	return got[0]
}
