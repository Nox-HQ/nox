package sarif

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// GitHub Code Scanning rates an alert by the `security-severity` of the rule
// descriptor its result points at, and by nothing on the result itself: a
// result's `level` moves it between error, warning and note, never between
// critical, high, medium and low. So a finding whose severity differs from its
// rule's — a reachability downgrade, a severity_override, a published example,
// a VULN-001 advisory at its own severity — was shown on GitHub at the rule's
// rating while every nox report said something else.
//
// The invariant these tests hold: the descriptor a result references carries
// that result's own severity, and which descriptor that is depends on the
// finding alone, never on what else the scan found.

func declaredRules() *rules.RuleSet {
	rs := rules.NewRuleSet()
	rs.Add(&rules.Rule{
		ID:          "rule-001",
		Version:     "1.0.0",
		Description: "Detects hardcoded credentials in source files",
		Severity:    findings.SeverityHigh,
		Confidence:  findings.ConfidenceMedium,
		MatcherType: "regex",
		Pattern:     `secret`,
		Tags:        []string{"secrets", "security"},
		Metadata:    map[string]string{"cwe": "CWE-798"},
		Remediation: "Rotate the credential and load it from a secret store.",
		References:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
	})
	return rs
}

func finding(rule string, sev findings.Severity, file string) findings.Finding {
	return findings.Finding{
		RuleID:      rule,
		Severity:    sev,
		Message:     "m",
		Fingerprint: rule + "|" + file + "|" + string(sev),
		Location:    findings.Location{FilePath: file, StartLine: 1},
	}
}

// The two ways nox builds a reporter: the CLI embeds the whole catalog, the MCP
// surface does not (a response budget) but still knows each rule's severity.
func reporterModes() map[string]func() *Reporter {
	return map[string]func() *Reporter{
		"catalog embedded": func() *Reporter { return NewReporter("t", declaredRules()) },
		"catalog not embedded": func() *Reporter {
			r := NewReporter("t", nil)
			r.Declared = declaredRules()
			return r
		},
	}
}

func generateFrom(t *testing.T, r *Reporter, fs ...findings.Finding) Report {
	t.Helper()
	set := findings.NewFindingSet()
	for _, f := range fs {
		set.Add(f)
	}
	data, err := r.Generate(set)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return mustUnmarshal(t, data)
}

func TestEveryResultIsDescribedAtItsOwnSeverity(t *testing.T) {
	cases := []struct {
		name       string
		f          findings.Finding
		wantRuleID string
		wantSS     string // "" means no security-severity at all
		wantLevel  string
	}{
		{"at the rule's own severity keeps the rule's id",
			finding("rule-001", findings.SeverityHigh, "a.go"), "rule-001", "8.0", "error"},
		{"raised above the rule",
			finding("rule-001", findings.SeverityCritical, "a.go"), "rule-001/critical", "9.5", "error"},
		{"lowered to medium",
			finding("rule-001", findings.SeverityMedium, "a.go"), "rule-001/medium", "5.5", "warning"},
		{"lowered to low",
			finding("rule-001", findings.SeverityLow, "a.go"), "rule-001/low", "2.0", "note"},
		{"lowered to info carries no security severity",
			finding("rule-001", findings.SeverityInfo, "a.go"), "rule-001/info", "", "note"},
		{"a rule nox declares nothing about is named by its severity",
			finding("PLUGIN-1", findings.SeverityHigh, "a.go"), "PLUGIN-1/high", "8.0", "error"},
	}
	for mode, mk := range reporterModes() {
		for _, tc := range cases {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				run := generateFrom(t, mk(), tc.f).Runs[0]
				if len(run.Results) != 1 {
					t.Fatalf("want 1 result, got %d", len(run.Results))
				}
				res := run.Results[0]
				if res.RuleID != tc.wantRuleID {
					t.Errorf("ruleId = %q, want %q", res.RuleID, tc.wantRuleID)
				}
				desc := run.Tool.Driver.Rules[res.RuleIndex]
				if desc.ID != res.RuleID {
					t.Fatalf("ruleIndex %d points at %q, result says %q", res.RuleIndex, desc.ID, res.RuleID)
				}
				ss, _ := desc.Properties["security-severity"].(string)
				if ss != tc.wantSS {
					t.Errorf("descriptor security-severity = %q, want %q", ss, tc.wantSS)
				}
				if desc.DefaultConfiguration.Level != tc.wantLevel || res.Level != tc.wantLevel {
					t.Errorf("levels: descriptor %q, result %q, want %q",
						desc.DefaultConfiguration.Level, res.Level, tc.wantLevel)
				}
			})
		}
	}
}

// Before, a reporter without the catalog described each rule by whichever of
// its findings sorted first. One info finding sorting ahead of a real leak took
// the leak's security severity away on GitHub — and fixing that first finding
// changed every other alert's rating.
func TestARulesIdentityDoesNotDependOnItsOtherFindings(t *testing.T) {
	leak := finding("rule-001", findings.SeverityHigh, "z.go")
	for mode, mk := range reporterModes() {
		t.Run(mode, func(t *testing.T) {
			alone := generateFrom(t, mk(), leak).Runs[0]
			crowded := generateFrom(t, mk(),
				finding("rule-001", findings.SeverityInfo, "a.go"),
				finding("rule-001", findings.SeverityLow, "b.go"),
				leak,
			).Runs[0]
			got := func(run Run) (string, string) {
				for _, res := range run.Results {
					if res.Fingerprints["nox/v1"] == leak.Fingerprint {
						ss, _ := run.Tool.Driver.Rules[res.RuleIndex].Properties["security-severity"].(string)
						return res.RuleID, ss
					}
				}
				t.Fatal("leak missing from results")
				return "", ""
			}
			idA, ssA := got(alone)
			idC, ssC := got(crowded)
			if idA != idC || ssA != ssC {
				t.Errorf("alone: %s at %s; beside other findings: %s at %s", idA, ssA, idC, ssC)
			}
			if ssC != "8.0" {
				t.Errorf("the leak is rated %q on GitHub, want 8.0", ssC)
			}
		})
	}
}

// A severity variant is the same check making a weaker or stronger claim, so it
// keeps the rule's description, help, tags and CWE, and names its parent.
func TestASeverityVariantKeepsItsRulesDescription(t *testing.T) {
	run := generateFrom(t, NewReporter("t", declaredRules()),
		finding("rule-001", findings.SeverityMedium, "a.go")).Runs[0]
	desc := run.Tool.Driver.Rules[run.Results[0].RuleIndex]
	if desc.ID != "rule-001/medium" {
		t.Fatalf("descriptor %q", desc.ID)
	}
	if desc.Help == nil || desc.HelpURI == "" || desc.FullDescription == nil {
		t.Errorf("variant lost its help: help=%v helpUri=%q full=%v", desc.Help, desc.HelpURI, desc.FullDescription)
	}
	if desc.Properties["cwe"] != "CWE-798" {
		t.Errorf("cwe = %v", desc.Properties["cwe"])
	}
	if tags, _ := desc.Properties["tags"].([]any); len(tags) != 2 {
		t.Errorf("tags = %v", desc.Properties["tags"])
	}
	if desc.Properties["parent-rule"] != "rule-001" {
		t.Errorf("parent-rule = %v", desc.Properties["parent-rule"])
	}
	if desc.ShortDescription.Text == "" {
		t.Error("variant has no short description")
	}
}

// An embedded catalog lists every rule once, at its declared severity, and a
// variant is added only when a result needs it.
func TestTheCatalogGrowsOnlyByTheVariantsInUse(t *testing.T) {
	run := generateFrom(t, NewReporter("t", declaredRules()),
		finding("rule-001", findings.SeverityHigh, "a.go"),
		finding("rule-001", findings.SeverityLow, "b.go"),
		finding("rule-001", findings.SeverityLow, "c.go"),
	).Runs[0]
	var ids []string
	for _, d := range run.Tool.Driver.Rules {
		ids = append(ids, d.ID)
	}
	if len(ids) != 2 || ids[0] != "rule-001" || ids[1] != "rule-001/low" {
		t.Errorf("catalog = %v, want [rule-001 rule-001/low]", ids)
	}
}
