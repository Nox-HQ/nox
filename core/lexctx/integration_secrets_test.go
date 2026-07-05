package lexctx_test

// This integration test proves the package's thesis end to end: it runs the
// REAL secrets analyzer over a realistic fixture, then applies lexctx as an
// opt-in post-filter and shows a concrete before/after drop in finding count —
// without the two comment/blob false positives, keeping the one true positive.
//
// It lives in an external test package (lexctx_test) and imports the secrets
// analyzer, which is the same direction a future integration would take. It
// does NOT modify the analyzer: the filter is applied to the analyzer's output,
// demonstrating that adoption is a small, additive change.

import (
	"testing"

	"github.com/nox-hq/nox/core/analyzers/secrets"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
)

// suppressNonCodeFindings returns the findings that survive the lexctx gate for
// the given file: a finding is dropped when its reported location is inside a
// comment or a string data blob. This is the ~5-line adapter a real analyzer
// would add to consume lexctx.
func suppressNonCodeFindings(path string, content []byte, in []findings.Finding) []findings.Finding {
	lang := lexctx.LangFromPath(path)
	if lang == lexctx.LangUnknown {
		return in // graceful degrade: no language, no filtering
	}
	kept := make([]findings.Finding, 0, len(in))
	for i := range in {
		f := in[i]
		start := lexctx.LineColToOffset(content, f.Location.StartLine, f.Location.StartColumn)
		end := lexctx.LineColToOffset(content, f.Location.EndLine, f.Location.EndColumn)
		if end <= start {
			end = start + 1
		}
		// Drop comments always; drop string matches only when the string is a
		// data blob (SuppressNonCode encodes both), so real hardcoded secrets in
		// short string literals are preserved.
		if lexctx.SuppressNonCode(lang, content, start, end) {
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

func TestSecretsAnalyzer_LexctxCollapsesFalsePositives(t *testing.T) {
	// A real AWS access-key ID: AKIA + 16 chars from [A-Z2-7].
	const awsKey = "AKIAIOSFODNN7EXAMPLE"

	// A realistic .ts file. The key appears three times:
	//   1. as a genuine hardcoded secret in a short string literal (TRUE +),
	//   2. buried in a base64 SVG data-URI blob (FALSE +),
	//   3. inside a `//` comment (FALSE +).
	// The base64 chunks are broken with '/' so only the key is a key-shaped run.
	src := []byte("" +
		"export const awsKey = \"" + awsKey + "\";\n" +
		"export const icon = \"data:image/svg+xml;base64,PHN2/" + awsKey + "/Zz4=\";\n" +
		"// rotate legacy key " + awsKey + " before removing this line\n" +
		"export function useKey() { return awsKey; }\n")
	const path = "src/config.ts"

	analyzer := secrets.NewAnalyzer()
	raw, err := analyzer.ScanFile(path, src)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}

	// Count how many findings reference the AWS key rule (SEC-2 family) before
	// filtering. We expect the naive scan to fire on all three occurrences.
	rawKeyHits := countAWSKeyFindings(raw)
	if rawKeyHits < 3 {
		t.Fatalf("precondition: expected the raw scan to fire >=3 times on the "+
			"AWS key (code + blob + comment), got %d (total findings %d)",
			rawKeyHits, len(raw))
	}

	filtered := suppressNonCodeFindings(path, src, raw)
	filteredKeyHits := countAWSKeyFindings(filtered)

	if filteredKeyHits != 1 {
		t.Fatalf("expected exactly 1 AWS-key finding after lexctx gate "+
			"(the real hardcoded secret), got %d", filteredKeyHits)
	}

	// The surviving key finding must be the one on line 1 (the code assignment),
	// not the blob (line 2) or comment (line 3).
	survivor := firstAWSKeyFinding(filtered)
	if survivor == nil {
		t.Fatal("no surviving AWS-key finding")
	}
	if survivor.Location.StartLine != 1 {
		t.Errorf("survivor should be the line-1 code secret, got line %d",
			survivor.Location.StartLine)
	}

	t.Logf("FP collapse: AWS-key findings %d -> %d (dropped blob + comment)",
		rawKeyHits, filteredKeyHits)
}

// countAWSKeyFindings counts findings whose match is the AWS access-key ID rule
// (SEC-001 in the builtin set).
func countAWSKeyFindings(fs []findings.Finding) int {
	c := 0
	for i := range fs {
		if isAWSKeyRule(fs[i].RuleID) {
			c++
		}
	}
	return c
}

func firstAWSKeyFinding(fs []findings.Finding) *findings.Finding {
	for i := range fs {
		if isAWSKeyRule(fs[i].RuleID) {
			return &fs[i]
		}
	}
	return nil
}

func isAWSKeyRule(ruleID string) bool {
	// SEC-001 is the AWS access-key ID rule in the builtin secrets set.
	return ruleID == "SEC-001"
}
