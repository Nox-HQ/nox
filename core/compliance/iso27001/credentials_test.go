package iso27001

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/catalog"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/report"
)

// A literal database password in a Kubernetes env block is an authentication
// secret written into the repository. Secret scanning does not see it (the
// value sits beside a `name:` key), so A.5.17 read "checks ran, nothing open".
func TestLiteralCredentialInInfrastructureOpensAuthenticationInformation(t *testing.T) {
	for _, rule := range []string{"IAC-502", "IAC-503"} {
		in := inputs()["clean"]
		in.Report.Findings = []findings.Finding{finding(rule, "high", findings.StatusNew, map[string]string{"cwe": "CWE-798"})}
		c := byID(t, Assess(in), "A.5.17")
		if c.Status != OpenIssues {
			t.Fatalf("%s: A.5.17 = %s, want open_issues", rule, c.Status)
		}
		var cited bool
		for _, e := range c.Evidence {
			for _, r := range e.Rules {
				cited = cited || r == rule
			}
		}
		if !cited {
			t.Errorf("%s: A.5.17 evidence does not cite the rule: %+v", rule, c.Evidence)
		}
	}
}

// The addition must not make a repository with no infrastructure look worse: a
// source that can only add open issues has no say when it finds nothing.
func TestInfrastructureCredentialSourceIsSilentWhenItFindsNothing(t *testing.T) {
	c := byID(t, Assess(inputs()["clean"]), "A.5.17")
	if c.Status != SupportingEvidence {
		t.Fatalf("clean A.5.17 = %s, want supporting_evidence", c.Status)
	}
	if len(c.Evidence) != 1 || len(c.Gaps) != 0 {
		t.Errorf("a clean scan gained evidence or gaps from the additive source: %+v %v", c.Evidence, c.Gaps)
	}
}

func TestAdditiveCredentialSourceNeedsItsScope(t *testing.T) {
	in := inputs()["scoped"] // only the secrets scope ran
	in.Report.Findings = []findings.Finding{finding("IAC-502", "high", findings.StatusNew, nil)}
	c := byID(t, Assess(in), "A.5.17")
	if c.Status == OpenIssues {
		t.Errorf("an IAC finding in a scan that never ran the iac scope opened A.5.17")
	}
}

// Every other rule the 2026-10 additions introduced lands on the control it
// bears on. The prefix-matched ones are listed so a rename cannot orphan them.
func TestRecentRulesLandOnTheirControls(t *testing.T) {
	cases := []struct{ rule, control string }{
		{"IAC-502", "A.5.17"}, {"IAC-503", "A.5.17"},
		{"IAC-504", "A.5.23"}, {"IAC-504", "A.8.9"}, {"IAC-504", "A.8.12"},
		{"IAC-302", "A.5.23"}, {"IAC-302", "A.8.9"},
		{"IAC-028", "A.5.23"}, {"IAC-028", "A.8.9"},
		{"MCP-002", "A.8.27"}, {"MCP-003", "A.8.27"},
		{"MCP-025", "A.8.27"}, {"MCP-025", "A.5.21"},
		{"AI-AGENT-009", "A.8.27"}, {"AI-AGENT-009", "A.8.28"},
		{"AUTHZ-001", "A.8.28"},
	}
	for _, c := range cases {
		in := inputs()["clean"]
		in.Report.Findings = []findings.Finding{finding(c.rule, "high", findings.StatusNew, nil)}
		if got := byID(t, Assess(in), c.control); got.Status != OpenIssues {
			t.Errorf("%s does not open %s (status %s)", c.rule, c.control, got.Status)
		}
	}
}

// Authorization leads are hints. They must not be counted as findings, and
// they must not vanish from the control they bear on either.
func TestAuthorizationLeadsAreNamedAsUnconfirmedOnSecureCoding(t *testing.T) {
	in := inputs()["clean"]
	in.Report.Leads = []report.Lead{{Category: "bola", RuleID: "AUTHZ-001", Route: "GET /orders/:id", FilePath: "src/orders.js", Line: 4}}
	c := byID(t, Assess(in), "A.8.28")
	if c.Status == OpenIssues {
		t.Fatalf("a lead was counted as an open finding")
	}
	if c.Status == SupportingEvidence {
		t.Errorf("A.8.28 with unconfirmed authorization leads reads as supporting evidence")
	}
	if !strings.Contains(strings.Join(c.Gaps, " "), "1 authorization lead") {
		t.Errorf("leads not named: %v", c.Gaps)
	}
	if none := byID(t, Assess(inputs()["clean"]), "A.8.28"); strings.Contains(strings.Join(none.Gaps, " "), "authorization lead") {
		t.Errorf("a lead gap appeared with no leads: %v", none.Gaps)
	}
}

// Hard-coded credential rules are found by what they do, not remembered by
// ID: every built-in rule whose description says it writes a literal secret
// into configuration is either mapped to A.5.17 or excluded here with a reason.
func TestEveryLiteralCredentialRuleIsMappedOrExcludedWithAReason(t *testing.T) {
	excluded := map[string]string{
		"IAC-224": "an SSH authorized key is a public key, not authentication information",
		"IAC-260": "asks to verify key rotation; no credential is present in the file",
		"IAC-272": "a variable default flagged for review, not a secret value",
		"IAC-092": "reports the absence of a managed identity, not a credential",
		"IAC-096": "reports the absence of a managed identity, not a credential",
		"IAC-113": "reports the absence of workload identity, not a credential",
		"IAC-151": "reports static cloud credentials in a workflow without naming a value",
		"AI-025":  "an API key reaching the code through an environment variable, which is the recommended form",
		"AI-038":  "an embedding key stored with vectors; storage, not a literal in configuration",
	}
	mapped := map[string]bool{}
	for _, d := range controls {
		if d.id != "A.5.17" {
			continue
		}
		for _, s := range d.sources {
			for _, id := range s.ids {
				mapped[id] = true
			}
		}
	}
	for _, r := range catalog.Rules() {
		if r.Metadata["cwe"] != "CWE-798" || strings.HasPrefix(r.ID, "SEC-") {
			continue
		}
		if !mapped[r.ID] && excluded[r.ID] == "" {
			t.Errorf("%s (%s) is a CWE-798 rule that is neither mapped to A.5.17 nor excluded with a reason", r.ID, r.Description)
		}
		if mapped[r.ID] && excluded[r.ID] != "" {
			t.Errorf("%s is both mapped and excluded", r.ID)
		}
	}
}
