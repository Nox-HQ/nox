package assess

import (
	"sort"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// span is where a secret finding sits: a line and the columns of its match.
type span struct{ line, endLine, from, to int }

func secretAt(rule, sev, conf, file string, s span) findings.Finding {
	return findings.Finding{
		RuleID: rule, Severity: findings.Severity(sev), Confidence: findings.Confidence(conf),
		Location: findings.Location{
			FilePath: file, StartLine: s.line, EndLine: s.endLine, StartColumn: s.from, EndColumn: s.to,
		},
		Message:     rule + " detected",
		Fingerprint: rule + "@" + file + ":" + strings.Repeat("i", s.line) + strings.Repeat("c", s.from),
	}
}

func codeIssuesOf(ff ...findings.Finding) []Issue {
	out := codeIssues(Input{Findings: ff}, make([]bool, len(ff)))
	sort.Slice(out, func(i, j int) bool { return out[i].Summary < out[j].Summary })
	return out
}

// Two rules that report the same value report one thing to do. The analyzer
// keeps both findings on purpose (two providers of equal standing each claim
// the value), and the assessment used to turn that into two issues: "Lob API
// Key detected [SEC-070] at .env.example:71" and "Lob API key [SEC-262] at
// .env.example:71". One key, rotated once.
func TestOneValueIsOneIssue(t *testing.T) {
	cases := []struct {
		name     string
		ff       []findings.Finding
		want     []string // per issue: the rule label its summary carries
		rules    []string // per issue: the rule that stands for it
		findings []int    // per issue: how many findings it stands for
	}{
		{
			name: "two provider rules on one key",
			ff: []findings.Finding{
				secretAt("SEC-070", "high", "medium", ".env.example", span{71, 71, 9, 49}),
				secretAt("SEC-262", "high", "medium", ".env.example", span{71, 71, 1, 49}),
			},
			want: []string{"[SEC-070, also SEC-262] at .env.example:71"}, rules: []string{"SEC-070"}, findings: []int{2},
		},
		{
			name: "the stronger claim stands for the value",
			ff: []findings.Finding{
				secretAt("SEC-299", "high", "medium", "key.pem", span{1, 28, 1, 26}),
				secretAt("SEC-004", "critical", "high", "key.pem", span{1, 2, 1, 65}),
			},
			want: []string{"[SEC-004, also SEC-299] at key.pem:1"}, rules: []string{"SEC-004"}, findings: []int{2},
		},
		{
			name: "a rule's other places stay with the value they share",
			ff: []findings.Finding{
				secretAt("SEC-001", "high", "high", "a.py", span{76, 76, 22, 42}),
				secretAt("SEC-001", "high", "high", "a.py", span{90, 90, 5, 25}),
				secretAt("SEC-508", "high", "medium", "a.py", span{76, 76, 22, 42}),
			},
			want: []string{"[SEC-001, also SEC-508] at a.py:76, a.py:90"}, rules: []string{"SEC-001"}, findings: []int{3},
		},
		{
			name: "a place only the second rule reports is still its own issue",
			ff: []findings.Finding{
				secretAt("SEC-001", "high", "high", "a.py", span{76, 76, 22, 42}),
				secretAt("SEC-508", "high", "medium", "a.py", span{76, 76, 22, 42}),
				secretAt("SEC-508", "high", "medium", "b.py", span{3, 3, 1, 21}),
			},
			want:  []string{"[SEC-001, also SEC-508] at a.py:76", "[SEC-508] at b.py:3"},
			rules: []string{"SEC-001", "SEC-508"}, findings: []int{2, 1},
		},
		{
			name: "two values on one line are two issues",
			ff: []findings.Finding{
				secretAt("SEC-001", "high", "high", "a.py", span{5, 5, 1, 21}),
				secretAt("SEC-030", "critical", "high", "a.py", span{5, 5, 30, 62}),
			},
			want: []string{"[SEC-001] at a.py:5", "[SEC-030] at a.py:5"}, rules: []string{"SEC-001", "SEC-030"}, findings: []int{1, 1},
		},
		{
			name: "a wide match does not join the two values inside it",
			ff: []findings.Finding{
				secretAt("SEC-161", "medium", "medium", "a.json", span{1, 1, 1, 200}),
				secretAt("SEC-001", "high", "high", "a.json", span{1, 1, 10, 30}),
				secretAt("SEC-030", "critical", "high", "a.json", span{1, 1, 60, 92}),
			},
			want:  []string{"[SEC-001] at a.json:1", "[SEC-030, also SEC-161] at a.json:1"},
			rules: []string{"SEC-001", "SEC-030"}, findings: []int{1, 2},
		},
		{
			name: "an observation is not a credential and is not folded into one",
			ff: []findings.Finding{
				secretAt("SEC-085", "high", "high", "a.py", span{5, 5, 1, 80}),
				secretAt("SEC-372", "info", "medium", "a.py", span{5, 5, 20, 80}),
			},
			want: []string{"[SEC-085] at a.py:5", "[SEC-372] at a.py:5"}, rules: []string{"SEC-085", "SEC-372"}, findings: []int{1, 1},
		},
		{
			name: "rules outside the secrets family share a line without sharing a value",
			ff: []findings.Finding{
				secretAt("IAC-007", "critical", "high", "k8s.yaml", span{2, 2, 1, 20}),
				secretAt("IAC-040", "critical", "high", "k8s.yaml", span{2, 2, 1, 20}),
			},
			want: []string{"[IAC-007] at k8s.yaml:2", "[IAC-040] at k8s.yaml:2"}, rules: []string{"IAC-007", "IAC-040"}, findings: []int{1, 1},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := codeIssuesOf(c.ff...)
			if len(got) != len(c.want) {
				t.Fatalf("%d issues, want %d: %+v", len(got), len(c.want), summaries(got))
			}
			total := 0
			for i, is := range got {
				if !strings.Contains(is.Summary, c.want[i]) {
					t.Errorf("issue %d: %q lacks %q", i, is.Summary, c.want[i])
				}
				if is.RuleID != c.rules[i] {
					t.Errorf("issue %d: rule %s, want %s", i, is.RuleID, c.rules[i])
				}
				if is.Findings != c.findings[i] || len(is.Fingerprints) != c.findings[i] {
					t.Errorf("issue %d: stands for %d findings (%d fingerprints), want %d",
						i, is.Findings, len(is.Fingerprints), c.findings[i])
				}
				total += is.Findings
			}
			if total != len(c.ff) {
				t.Errorf("the issues stand for %d findings, the scan reported %d: none may leave", total, len(c.ff))
			}
		})
	}
}

func summaries(is []Issue) []string {
	out := make([]string, len(is))
	for i := range is {
		out[i] = is[i].Summary
	}
	return out
}

// The value a merged issue stands for is rated by its strongest finding, the
// same rule every other issue follows.
func TestMergedIssueKeepsTheStrongestRating(t *testing.T) {
	got := codeIssuesOf(
		secretAt("SEC-299", "high", "medium", "key.pem", span{1, 28, 1, 26}),
		secretAt("SEC-004", "critical", "high", "key.pem", span{1, 2, 1, 65}),
	)
	if len(got) != 1 || got[0].Severity != findings.SeverityCritical || got[0].Confidence != findings.ConfidenceHigh || !got[0].Attention {
		t.Fatalf("got %+v", got)
	}
}

// published marks a finding the way the secrets analyzer does for a value its
// vendor prints in documentation: info, saying so, with the rule's rating kept.
func published(f findings.Finding, message string) findings.Finding {
	f.Metadata = map[string]string{
		findings.MetaValueClass:   findings.ValueClassPublishedExample,
		findings.MetaRuleSeverity: string(f.Severity),
	}
	f.Severity, f.Message = findings.SeverityInfo, message
	return f
}

// A published example is titled by what it is, never by the rule's "detected"
// sentence, does not need attention, and is still one issue when two rules
// report it. It is never folded into a real credential of the same rule, or
// into one that shares its line.
func TestPublishedExampleIsItsOwnIssue(t *testing.T) {
	const example = "AWS's published example access key ID: public documentation, not a credential"
	got := codeIssuesOf(
		published(secretAt("SEC-001", "high", "high", "README.md", span{6, 6, 23, 43}), example),
		published(secretAt("SEC-508", "high", "medium", "README.md", span{6, 6, 23, 43}), example),
		secretAt("SEC-001", "high", "high", "deploy.sh", span{3, 3, 9, 29}),
		secretAt("SEC-030", "critical", "high", "README.md", span{6, 6, 50, 82}),
		// A wider match over the example that claims some other value.
		secretAt("SEC-161", "medium", "medium", "README.md", span{6, 6, 1, 45}),
	)
	want := []struct {
		summary, rule, class string
		findings             int
		severity             findings.Severity
		attention            bool
	}{
		{example + " [SEC-001, also SEC-508] at README.md:6 (info severity", "SEC-001",
			findings.ValueClassPublishedExample, 2, findings.SeverityInfo, false},
		{"[SEC-001] at deploy.sh:3 (high severity", "SEC-001", "", 1, findings.SeverityHigh, true},
		{"[SEC-030] at README.md:6 (critical severity", "SEC-030", "", 1, findings.SeverityCritical, true},
		{"[SEC-161] at README.md:6 (medium severity", "SEC-161", "", 1, findings.SeverityMedium, false},
	}
	if len(got) != len(want) {
		t.Fatalf("%d issues, want %d: %+v", len(got), len(want), summaries(got))
	}
	for i, w := range want {
		is := got[i]
		if !strings.Contains(is.Summary, w.summary) {
			t.Errorf("issue %d: %q lacks %q", i, is.Summary, w.summary)
		}
		if is.RuleID != w.rule || is.ValueClass != w.class || is.Findings != w.findings ||
			is.Severity != w.severity || is.Attention != w.attention {
			t.Errorf("issue %d = rule %s class %q findings %d severity %s attention %v, want %+v",
				i, is.RuleID, is.ValueClass, is.Findings, is.Severity, is.Attention, w)
		}
	}
}

// testMode marks a finding the way the secrets analyzer does for a key to a
// vendor's test environment: medium, saying so, with the rule's rating kept.
func testMode(f findings.Finding, message string) findings.Finding {
	f.Metadata = map[string]string{
		findings.MetaValueClass:   findings.ValueClassTestMode,
		findings.MetaRuleSeverity: string(f.Severity),
	}
	f.Severity, f.Message = findings.SeverityMedium, message
	return f
}

// A test-mode key two rules report is one issue, titled by what the key is, and
// it is not the live key of the same rules: that one keeps its own issue and
// its own rating, so the list still leads with it.
func TestTestModeKeyIsItsOwnIssue(t *testing.T) {
	const title = "Test-mode credential: Lob API Key detected"
	const msg = title + ". It reaches the vendor's test environment and no live data."
	got := codeIssuesOf(
		testMode(secretAt("SEC-070", "high", "medium", ".env.test", span{2, 2, 13, 53}), msg),
		testMode(secretAt("SEC-262", "high", "medium", ".env.test", span{2, 2, 1, 54}), msg),
		secretAt("SEC-070", "high", "medium", ".env", span{2, 2, 13, 53}),
		secretAt("SEC-262", "high", "medium", ".env", span{2, 2, 1, 54}),
	)
	want := []struct {
		summary, class string
		severity       findings.Severity
	}{
		{"[SEC-070, also SEC-262] at .env:2 (high severity", "", findings.SeverityHigh},
		{title + " [SEC-070, also SEC-262] at .env.test:2 (medium severity", findings.ValueClassTestMode, findings.SeverityMedium},
	}
	if len(got) != len(want) {
		t.Fatalf("%d issues, want %d: %+v", len(got), len(want), summaries(got))
	}
	for i, w := range want {
		is := got[i]
		if !strings.Contains(is.Summary, w.summary) {
			t.Errorf("issue %d: %q lacks %q", i, is.Summary, w.summary)
		}
		if is.ValueClass != w.class || is.Severity != w.severity || is.Findings != 2 {
			t.Errorf("issue %d = class %q severity %s findings %d, want %+v with 2 findings",
				i, is.ValueClass, is.Severity, is.Findings, w)
		}
	}
}
