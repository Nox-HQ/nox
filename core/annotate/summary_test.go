package annotate

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

func finding(rule string, sev findings.Severity, path string, line int) findings.Finding {
	return findings.Finding{RuleID: rule, Severity: sev, Message: rule, Location: findings.Location{FilePath: path, StartLine: line}}
}

func TestSelectAppliesMinimumSeverityAndCap(t *testing.T) {
	ff := []findings.Finding{
		finding("A", findings.SeverityLow, "a", 1),
		finding("B", findings.SeverityCritical, "b", 2),
		finding("C", findings.SeverityMedium, "c", 3),
		finding("D", findings.SeverityInfo, "d", 4),
		finding("E", findings.SeverityHigh, "e", 5),
	}
	ids := func(ff []findings.Finding) string {
		var s []string
		for i := range ff {
			s = append(s, ff[i].RuleID)
		}
		return strings.Join(s, ",")
	}
	for _, c := range []struct {
		opts Options
		want string
	}{
		{Options{}, "A,B,C,D,E"}, // no options: annotate's behaviour is unchanged
		{Options{MinSeverity: findings.SeverityMedium}, "B,C,E"},
		{Options{MinSeverity: findings.SeverityLow, MaxComments: 2}, "B,E"}, // worst first under a cap
		{Options{MaxComments: 3}, "B,E,C"},
	} {
		if got := ids(Select(ff, c.opts)); got != c.want {
			t.Errorf("Select(%+v) = %s, want %s", c.opts, got, c.want)
		}
	}
}

// The summary counts every finding in the report, by severity, whatever was
// posted inline: issue #1016's comment said "Total 2" over five zeros.
func TestSummaryCountsEverySeverity(t *testing.T) {
	ff := []findings.Finding{
		finding("IAC-306", findings.SeverityMedium, ".github/workflows/nox.yml", 11),
		finding("IAC-309", findings.SeverityLow, ".github/workflows/ci.yml", 14),
		finding("SEC-1", findings.SeverityCritical, "x", 1),
		finding("SEC-2", findings.SeverityCritical, "y", 2),
	}
	s := Summary(ff, 3, Options{MaxComments: 25, MinSeverity: findings.SeverityLow})
	for _, want := range []string{
		"| :red_circle: Critical | 2 |",
		"| :orange_circle: High | 0 |",
		"| :yellow_circle: Medium | 1 |",
		"| :large_blue_circle: Low | 1 |",
		"| :white_circle: Info | 0 |",
		"| **Total** | **4** |",
		"3 inline comment(s) posted (max: 25, min severity: low).",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("summary lacks %q:\n%s", want, s)
		}
	}
	if s2 := Summary(ff, 0, Options{}); !strings.Contains(s2, "(max: none, min severity: any)") {
		t.Errorf("unbounded summary:\n%s", s2)
	}
}
