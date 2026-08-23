package fix

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

func vuln(eco, pkg, from, fixed string) findings.Finding {
	return findings.Finding{
		RuleID:   "VULN-001",
		Location: findings.Location{FilePath: "go.mod"},
		Metadata: map[string]string{
			"ecosystem": eco, "package": pkg, "version": from, "fixed_in": fixed,
		},
	}
}

func goVuln(pkg, from, fixed string) findings.Finding { return vuln("go", pkg, from, fixed) }

// A remediation must never move a package backwards or onto a prerelease. This
// guard is the reason PlanUpgrades exists in the domain: the MCP fix_plan tool
// used to lack it and could show an agent a downgrade the CLI would refuse.
func TestPlanUpgradesNeverDowngrades(t *testing.T) {
	tests := []struct {
		name  string
		items []findings.Finding
		want  string // expected To; "" means no action planned
	}{
		{"an ordinary forward fix is planned", []findings.Finding{goVuln("golang.org/x/crypto", "0.51.0", "0.54.0")}, "0.54.0"},
		{"a fixed_in below installed is not an upgrade", []findings.Finding{goVuln("golang.org/x/crypto", "0.54.0", "0.51.0")}, ""},
		{"fixed_in equal to installed is already satisfied", []findings.Finding{goVuln("golang.org/x/crypto", "0.54.0", "0.54.0")}, ""},
		{"several advisories resolve to the highest fix", []findings.Finding{
			goVuln("golang.org/x/crypto", "0.50.0", "0.51.0"),
			goVuln("golang.org/x/crypto", "0.50.0", "0.54.0"),
			goVuln("golang.org/x/crypto", "0.50.0", "0.52.0"),
		}, "0.54.0"},
		{"highest wins regardless of order", []findings.Finding{
			goVuln("golang.org/x/crypto", "0.50.0", "0.54.0"),
			goVuln("golang.org/x/crypto", "0.50.0", "0.51.0"),
		}, "0.54.0"},
		{"a prerelease fix is not selected for a stable install", []findings.Finding{goVuln("google.golang.org/grpc", "1.79.3", "1.81.0-dev")}, ""},
		{"a prerelease install may move to a prerelease fix", []findings.Finding{goVuln("google.golang.org/grpc", "1.80.0-dev", "1.81.0-dev")}, "1.81.0-dev"},
		{"an unparseable installed version is skipped", []findings.Finding{goVuln("example.com/x", "main-20260101", "1.2.3")}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			plan := PlanUpgrades(tc.items, Options{IncludeMajor: true})
			if tc.want == "" {
				if len(plan.Actions) != 0 {
					t.Fatalf("expected no action, got %s -> %s", plan.Actions[0].From, plan.Actions[0].To)
				}
				return
			}
			if len(plan.Actions) != 1 {
				t.Fatalf("expected exactly 1 action, got %d: %+v", len(plan.Actions), plan.Actions)
			}
			if got := plan.Actions[0].To; got != tc.want {
				t.Errorf("To = %s, want %s", got, tc.want)
			}
		})
	}
}

// Two workspaces on the same vulnerable version are two upgrades: collapsing
// them by package name alone leaves one still vulnerable. This is the monorepo
// keying the MCP copy lacked.
func TestPlanUpgradesKeysByManifestDirectory(t *testing.T) {
	a := goVuln("golang.org/x/crypto", "0.51.0", "0.54.0")
	a.Location.FilePath = "apps/web/go.mod"
	b := goVuln("golang.org/x/crypto", "0.51.0", "0.54.0")
	b.Location.FilePath = "services/api/go.mod"
	plan := PlanUpgrades([]findings.Finding{a, b}, Options{})
	if len(plan.Actions) != 2 {
		t.Fatalf("two workspaces should yield two upgrades, got %d", len(plan.Actions))
	}
}

// nox fix cannot edit maven/gradle build files, so those must be SKIPPED, not
// dressed up as actionable. The MCP copy used to emit a fake "upgrade in your
// build file" step the CLI would never run.
func TestPlanUpgradesSkipsEcosystemsNoxCannotDrive(t *testing.T) {
	for _, eco := range []string{"maven", "gradle", "swift", ""} {
		plan := PlanUpgrades([]findings.Finding{vuln(eco, "some/pkg", "1.0.0", "1.2.0")}, Options{})
		if len(plan.Actions) != 0 {
			t.Errorf("ecosystem %q must be skipped, got action %+v", eco, plan.Actions[0])
		}
		if plan.Skipped != 1 {
			t.Errorf("ecosystem %q should count as skipped, got Skipped=%d", eco, plan.Skipped)
		}
	}
}

// composer IS supported and must produce a non-empty, runnable command — the
// MCP copy emitted an empty command string for it.
func TestPlanUpgradesComposerHasACommand(t *testing.T) {
	plan := PlanUpgrades([]findings.Finding{vuln("composer", "monolog/monolog", "2.0.0", "2.9.3")}, Options{})
	if len(plan.Actions) != 1 {
		t.Fatalf("composer upgrade should be planned, got %d actions", len(plan.Actions))
	}
	if cmd := plan.Actions[0].Command(); cmd == "" {
		t.Error("composer action must have a non-empty command")
	}
}

// Command() must produce the operator-runnable form for every supported
// ecosystem — and never an empty string for one nox claims to support.
func TestCommandForEverySupportedEcosystem(t *testing.T) {
	for eco := range ecosystemCommands {
		a := UpgradeAction{Package: "pkg", To: "1.2.3", Ecosystem: eco}
		if a.Command() == "" {
			t.Errorf("supported ecosystem %q produced an empty command", eco)
		}
	}
}

func TestMajorBumpHeldBackByDefault(t *testing.T) {
	item := goVuln("example.com/x", "1.5.0", "2.0.0")
	if plan := PlanUpgrades([]findings.Finding{item}, Options{}); len(plan.Actions) != 0 || plan.MajorSkipped != 1 {
		t.Fatalf("major bump should be held back by default: actions=%d majorSkipped=%d", len(plan.Actions), plan.MajorSkipped)
	}
	if plan := PlanUpgrades([]findings.Finding{item}, Options{IncludeMajor: true}); len(plan.Actions) != 1 {
		t.Fatalf("major bump should apply with IncludeMajor, got %d actions", len(plan.Actions))
	}
}

func TestIsUpgrade(t *testing.T) {
	tests := []struct {
		from, to string
		want     bool
		why      string
	}{
		{"0.51.0", "0.54.0", true, "ordinary forward move"},
		{"0.54.0", "0.51.0", false, "downgrade"},
		{"0.54.0", "0.54.0", false, "already satisfied"},
		{"1.79.3", "1.81.0-dev", false, "stable must not adopt a prerelease"},
		{"1.80.0-dev", "1.81.0-dev", true, "prerelease may move within prereleases"},
		{"1.2.0-dev", "1.2.0", true, "prerelease to its release is forward"},
		{"1.9.0", "1.10.0", true, "numeric compare, not lexical: 10 > 9"},
		{"1.10.0", "1.9.0", false, "numeric compare, not lexical: 9 < 10"},
		{"v1.2.3", "v1.2.4", true, "leading v tolerated"},
		{"1.2", "1.2.1", true, "uneven component counts"},
		{"main-20260101", "1.2.3", false, "unparseable install"},
		{"1.2.3", "latest", false, "unparseable target"},
		{"", "1.2.3", true, "absent install: apply, do not drop coverage"},
		{"", "1.2.3-dev", false, "absent install still refuses a prerelease"},
	}
	for _, tc := range tests {
		t.Run(tc.why, func(t *testing.T) {
			if got := IsUpgrade(tc.from, tc.to); got != tc.want {
				t.Errorf("IsUpgrade(%q, %q) = %v, want %v — %s", tc.from, tc.to, got, tc.want, tc.why)
			}
		})
	}
}

func TestBestFix(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want string
	}{
		{"highest of several", []string{"0.51.0", "0.54.0", "0.52.0"}, "0.54.0"},
		{"order does not matter", []string{"0.54.0", "0.51.0"}, "0.54.0"},
		{"numeric not lexical", []string{"1.9.0", "1.10.0"}, "1.10.0"},
		{"release beats its prerelease", []string{"1.2.0-dev", "1.2.0"}, "1.2.0"},
		{"unparseable entries ignored", []string{"latest", "1.2.3"}, "1.2.3"},
		{"all unparseable yields nothing", []string{"latest", "main"}, ""},
		{"empty yields nothing", nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := BestFix(tc.in); got != tc.want {
				t.Errorf("BestFix(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
