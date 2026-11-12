package assess

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

func goDep(pkg, version, fixed string, sev findings.Severity, applicability string) findings.Finding {
	f := dep(pkg, version, fixed, sev, "fp-"+pkg+"-"+fixed)
	f.Location.FilePath = "go.mod"
	f.Metadata["ecosystem"] = "go"
	f.Metadata["applicability"] = applicability
	if applicability == "not_impacting" {
		f.Metadata["applicability_stopped_at"] = "symbol_used"
		f.Metadata["applicability_because"] = "negative"
	}
	return f
}

func onlyIssue(t *testing.T, ff ...findings.Finding) Issue {
	t.Helper()
	r := Build(Input{Findings: ff, Target: "."})
	if len(r.Issues) != 1 {
		t.Fatalf("got %d issues, want 1: %+v", len(r.Issues), r.Issues)
	}
	return r.Issues[0]
}

// The Go advisory database writes fixed versions without the module's "v"
// (0.58.1-0.2026…), and go.mod writes installed ones with it. A line reading
// "Upgrade x/crypto v0.58.0 to 0.58.1-…" names a version `go get` rejects.
// This one is a pseudo-version, which the planner will not move to on its own,
// so it arrives as a no-fix issue.
func TestDependencyLine(t *testing.T) {
	const pseudo = "0.58.1-0.20261009181718-2f1f834330b2"
	tests := []struct {
		name    string
		finding findings.Finding
		want    []string
		not     []string
	}{
		{
			name:    "an all-info group still states its severity",
			finding: goDep("golang.org/x/crypto", "v0.58.0", pseudo, findings.SeverityInfo, "not_impacting"),
			want:    []string{"(highest severity: info)"},
			not:     []string{"(highest severity: )"},
		},
		{
			name:    "the fixed version is spelled the way the installed one is",
			finding: goDep("golang.org/x/crypto", "v0.58.0", pseudo, findings.SeverityInfo, "not_impacting"),
			want:    []string{"golang.org/x/crypto v0.58.0 to v" + pseudo + " or later"},
		},
		{
			name:    "a planned upgrade is spelled the same way",
			finding: goDep("golang.org/x/net", "v0.40.0", "0.41.0", findings.SeverityHigh, "impacting"),
			want:    []string{"Upgrade golang.org/x/net v0.40.0 -> v0.41.0"},
		},
		{
			name:    "a finding shown not to impact the build says so on its line",
			finding: goDep("golang.org/x/crypto", "v0.58.0", pseudo, findings.SeverityInfo, "not_impacting"),
			want:    []string{"Not currently impacting this application: the affected package is not linked by this build."},
		},
		{
			name:    "a planned upgrade for an unlinked package says so too",
			finding: goDep("golang.org/x/net", "v0.40.0", "0.41.0", findings.SeverityInfo, "not_impacting"),
			want:    []string{"Upgrade golang.org/x/net v0.40.0 -> v0.41.0", "Not currently impacting this application"},
		},
		{
			name:    "an undetermined finding makes no such claim",
			finding: goDep("golang.org/x/net", "v0.40.0", "0.41.0", findings.SeverityHigh, "undetermined"),
			not:     []string{"Not currently impacting"},
		},
		{
			name:    "an unprefixed installed version is left alone",
			finding: dep("axios", "1.6.0", "1.8.2", findings.SeverityHigh, "fp-axios"),
			want:    []string{"Upgrade axios 1.6.0 -> 1.8.2"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := onlyIssue(t, tc.finding).Summary
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("summary %q\n  does not contain %q", got, w)
				}
			}
			for _, n := range tc.not {
				if strings.Contains(got, n) {
					t.Errorf("summary %q\n  contains %q", got, n)
				}
			}
		})
	}
}

// One impacting advisory in the group and the line stays an instruction: the
// note is about the whole group, never about part of it.
func TestNotImpactingNoteNeedsEveryFinding(t *testing.T) {
	a := goDep("golang.org/x/net", "v0.40.0", "0.41.0", findings.SeverityInfo, "not_impacting")
	b := goDep("golang.org/x/net", "v0.40.0", "0.42.0", findings.SeverityHigh, "impacting")
	got := onlyIssue(t, a, b).Summary
	if strings.Contains(got, "Not currently impacting") {
		t.Errorf("summary %q says the group does not impact the application; one of its two advisories does", got)
	}
	if !strings.Contains(got, "(highest severity: high)") {
		t.Errorf("summary %q lost the group's severity", got)
	}
}

// The fix plan reads the issue's FixedIn, so it is spelled the same way.
func TestNoFixIssueFixedInIsSpelledLikeTheInstalledVersion(t *testing.T) {
	is := onlyIssue(t, goDep("golang.org/x/crypto", "v0.58.0", "0.58.1-0.20261009181718-2f1f834330b2", findings.SeverityInfo, "not_impacting"))
	if is.FixedIn != "v0.58.1-0.20261009181718-2f1f834330b2" {
		t.Errorf("FixedIn = %q, want the v-prefixed spelling go.mod uses", is.FixedIn)
	}
}
