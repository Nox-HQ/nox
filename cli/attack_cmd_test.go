package main

import (
	"testing"
	"time"

	"github.com/nox-hq/nox/core/attack"
)

// splitCSV is shared with the baseline command; `nox attack run --fields`
// depends on it dropping empties and trimming, so it is pinned here.
func TestSplitCSV(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"single", "persona", []string{"persona"}},
		{"multiple", "persona,message", []string{"persona", "message"}},
		{"whitespace and empties", " persona , , message ,", []string{"persona", "message"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitCSV(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("splitCSV(%q) = %v, want %v", tt.in, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("splitCSV(%q) = %v, want %v", tt.in, got, tt.want)
				}
			}
		})
	}
}

func TestRenderPath(t *testing.T) {
	if got := renderPath(nil); got != "" {
		t.Errorf("renderPath(nil) = %q, want \"\"", got)
	}
	steps := []attack.PathStep{
		{Kind: "entry_point", ID: "issue.description", Label: "issue.description"},
		{Kind: "agent", ID: "triage", Label: "issue-triage"},
		// A step with no label falls back to its id rather than rendering a gap.
		{Kind: "tool", ID: "filesystem.read"},
	}
	want := "issue.description -> issue-triage -> filesystem.read"
	if got := renderPath(steps); got != want {
		t.Errorf("renderPath() = %q, want %q", got, want)
	}
}

// budgetFrom must overlay only what the caller actually set, so raising one
// limit does not silently reset the others to zero (which would mean "no limit"
// on an ACTIVE capability).
func TestBudgetFromOverlaysDefaults(t *testing.T) {
	def := attack.DefaultBudget()

	unchanged := budgetFrom(0, 0, 0)
	if unchanged != def {
		t.Errorf("budgetFrom with no overrides = %+v, want the defaults %+v", unchanged, def)
	}

	got := budgetFrom(7, 0, 0)
	if got.Attempts != 7 {
		t.Errorf("Attempts = %d, want 7", got.Attempts)
	}
	if got.NetworkRequests != def.NetworkRequests || got.Duration != def.Duration {
		t.Errorf("overriding attempts must not disturb the other budgets: %+v", got)
	}

	got = budgetFrom(0, 0, 90*time.Second)
	if got.Duration != 90*time.Second {
		t.Errorf("Duration = %s, want 90s", got.Duration)
	}
	if got.Attempts != def.Attempts {
		t.Errorf("overriding duration must not disturb the attempt budget: %+v", got)
	}
}

// The safe profile must be safe by wiring, not by policy: it selects a target
// that has no network capability at all.
func TestTargetForSafeProfileCannotReachTheNetwork(t *testing.T) {
	tgt := targetFor(attack.ProfileSafe, "http://example.invalid", "reply", time.Second)
	if _, ok := tgt.(*attack.SimTarget); !ok {
		t.Fatalf("profile safe selected %T, want *attack.SimTarget", tgt)
	}
	for _, p := range []attack.Profile{attack.ProfileSandbox, attack.ProfileStaging, attack.ProfileAuthorizedLive} {
		got := targetFor(p, "http://127.0.0.1:1", "reply", time.Second)
		if _, ok := got.(*attack.HTTPTarget); !ok {
			t.Errorf("profile %s selected %T, want *attack.HTTPTarget", p, got)
		}
	}
}

func TestPlural(t *testing.T) {
	if got := plural(1, "is", "es"); got != "is" {
		t.Errorf("plural(1) = %q, want \"is\"", got)
	}
	if got := plural(0, "is", "es"); got != "es" {
		t.Errorf("plural(0) = %q, want \"es\"", got)
	}
	if got := plural(2, "is", "es"); got != "es" {
		t.Errorf("plural(2) = %q, want \"es\"", got)
	}
}

// Every ACTIVE subcommand must refuse without --authorize. Exercising the real
// entry points means a future refactor that drops a guard fails here.
func TestActiveSubcommandsRefuseWithoutAuthorization(t *testing.T) {
	cases := []struct {
		name string
		run  func() int
	}{
		{"run", func() int {
			return runAttackRun([]string{"--profile", "sandbox", "--target", "http://127.0.0.1:1"})
		}},
		{"replay", func() int {
			return runAttackReplay([]string{"TRACE-1", "--target", "http://127.0.0.1:1"})
		}},
		{"regress", func() int {
			return runAttackRegress([]string{"--target", "http://127.0.0.1:1"})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.run(); got != 2 {
				t.Errorf("nox attack %s without --authorize exited %d, want 2 (refusal)", tc.name, got)
			}
		})
	}
}

func TestUnknownSubcommandsAreRejected(t *testing.T) {
	if got := runAttack([]string{"detonate"}); got != 2 {
		t.Errorf("unknown attack subcommand exited %d, want 2", got)
	}
	if got := runAttack(nil); got != 2 {
		t.Errorf("bare `nox attack` exited %d, want 2", got)
	}
}
