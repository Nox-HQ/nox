package explain_test

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/catalog"
	"github.com/nox-hq/nox/core/explain"
)

// A rule ID can cover several weaknesses: TAINT-005 reports code_injection
// (CWE-94, CWE-95, CWE-134) and unsafe_deserialization (CWE-502), and its rule
// lists all four. The finding knows which one it is. Classifying an eval()
// finding by the rule's list, or by whichever CWE the rule once happened to
// carry, names weaknesses this finding does not have.
func TestTheFindingsOwnCWEClassifiesIt(t *testing.T) {
	in := baseInputs()
	in.Finding.RuleID = "TAINT-005"
	in.Finding.Message = "Untrusted input (http_query via \"code\") reaches code_injection sink \"eval\" without sanitization — CWE-95."
	in.Finding.Metadata = map[string]string{"cwe": "CWE-95"}
	in.Rule = catalog.RuleMeta{
		ID:          "TAINT-005",
		Description: "Untrusted input reaches a code_injection or unsafe_deserialization sink (CWE-94, CWE-95, CWE-134, CWE-502) without sanitization",
		CWE:         "CWE-94, CWE-95, CWE-134, CWE-502",
	}

	e := explain.Explain(in)
	if !strings.Contains(e.PotentialImpact, "Classified as CWE-95.") {
		t.Errorf("PotentialImpact = %q, want it classified by the finding's own CWE-95", e.PotentialImpact)
	}
	if strings.Contains(e.PotentialImpact, "CWE-502") || strings.Contains(e.WhyItMatters, "(CWE-94, CWE-95, CWE-134, CWE-502).") {
		t.Errorf("the explanation classifies the finding by the rule's whole CWE list:\n%s\n%s", e.WhyItMatters, e.PotentialImpact)
	}

	// A finding that carries no CWE still gets the rule's.
	in.Finding.Metadata = nil
	in.Rule.CWE = "CWE-798"
	if e := explain.Explain(in); !strings.Contains(e.PotentialImpact, "Classified as CWE-798.") {
		t.Errorf("PotentialImpact = %q, want the rule's CWE when the finding has none", e.PotentialImpact)
	}
}
