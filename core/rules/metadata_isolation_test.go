package rules

import "testing"

// TestFindingMetadataIsNotShared is the regression test for a cross-finding
// contamination bug.
//
// The engine assigned rule.Metadata (one map instance) to every finding of a
// rule. Downstream passes write per-finding keys — the GHA context downgrade,
// the original-severity audit trail — so one finding's write mutated the shared
// map and appeared on every other finding of the same rule, including findings
// in unrelated files. Each finding must own its metadata.
func TestFindingMetadataIsNotShared(t *testing.T) {
	t.Parallel()

	rs := NewRuleSet()
	rs.Add(&Rule{
		ID: "X-1", Pattern: "secret", MatcherType: "regex",
		Severity: "high", Description: "d",
		Metadata: map[string]string{"cwe": "CWE-1"},
	})
	e := NewEngine(rs)

	m, err := e.ScanFile("a.go", []byte("secret one\nsecret two\n"))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(m) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(m))
	}

	m[0].Metadata["gha_context"] = "downgraded"
	if _, leaked := m[1].Metadata["gha_context"]; leaked {
		t.Error("writing metadata on one finding contaminated a sibling — the map is shared")
	}
	if m[0].Metadata["cwe"] != "CWE-1" {
		t.Error("the rule's own metadata did not reach the finding")
	}
}
