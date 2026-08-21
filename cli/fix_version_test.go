package main

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

func vuln(pkg, from, fixed string) findings.Finding {
	return findings.Finding{
		RuleID: "VULN-001",
		Metadata: map[string]string{
			"ecosystem": "go", "package": pkg, "version": from, "fixed_in": fixed,
		},
	}
}

// A remediation must never move a package backwards.
//
// planUpgrades took fixed_in straight from the advisory and never compared it
// to the installed version. When several advisories cover one package — nine,
// for golang.org/x/crypto — each produced its own action, they were applied in
// sequence, and the LAST one won regardless of order. felixgeelhaar/specular#51
// was that: x/crypto v0.54.0 -> v0.51.0, introducing nine critical advisories
// into a repo that scanned clean, in a PR titled "chore(security)".
func TestPlanUpgradesNeverDowngrades(t *testing.T) {
	tests := []struct {
		name  string
		items []findings.Finding
		want  string // expected toVersion; "" means no action planned
	}{
		{
			name:  "an ordinary forward fix is planned",
			items: []findings.Finding{vuln("golang.org/x/crypto", "0.51.0", "0.54.0")},
			want:  "0.54.0",
		},
		{
			name:  "a fixed_in below the installed version is not an upgrade",
			items: []findings.Finding{vuln("golang.org/x/crypto", "0.54.0", "0.51.0")},
			want:  "",
		},
		{
			name:  "fixed_in equal to installed is already satisfied",
			items: []findings.Finding{vuln("golang.org/x/crypto", "0.54.0", "0.54.0")},
			want:  "",
		},
		{
			// The specular shape: many advisories, one package, mixed fix
			// versions. The highest wins, and it must clear every advisory.
			name: "several advisories on one package resolve to the highest fix",
			items: []findings.Finding{
				vuln("golang.org/x/crypto", "0.50.0", "0.51.0"),
				vuln("golang.org/x/crypto", "0.50.0", "0.54.0"),
				vuln("golang.org/x/crypto", "0.50.0", "0.52.0"),
			},
			want: "0.54.0",
		},
		{
			// Same, with the highest listed first — order must not decide it.
			name: "highest wins regardless of advisory order",
			items: []findings.Finding{
				vuln("golang.org/x/crypto", "0.50.0", "0.54.0"),
				vuln("golang.org/x/crypto", "0.50.0", "0.51.0"),
			},
			want: "0.54.0",
		},
		{
			// felixgeelhaar/orbita#49: grpc pinned to v1.81.0-dev, a real
			// upstream tag but a development marker, not a release.
			name:  "a prerelease fix is not selected for a stable install",
			items: []findings.Finding{vuln("google.golang.org/grpc", "1.79.3", "1.81.0-dev")},
			want:  "",
		},
		{
			// If the install is already a prerelease, moving within them is
			// the caller's own territory and not ours to block.
			name:  "a prerelease install may move to a prerelease fix",
			items: []findings.Finding{vuln("google.golang.org/grpc", "1.80.0-dev", "1.81.0-dev")},
			want:  "1.81.0-dev",
		},
		{
			// Unknown/unparseable versions must not be silently "upgraded"
			// on a guess.
			name:  "an unparseable installed version is skipped",
			items: []findings.Finding{vuln("example.com/x", "main-20260101", "1.2.3")},
			want:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			plan := planUpgrades(tc.items, true)

			if tc.want == "" {
				if len(plan.actions) != 0 {
					t.Fatalf("expected no action, got %s -> %s",
						plan.actions[0].fromVer, plan.actions[0].toVersion)
				}
				return
			}
			if len(plan.actions) != 1 {
				t.Fatalf("expected exactly 1 action, got %d: %+v", len(plan.actions), plan.actions)
			}
			if got := plan.actions[0].toVersion; got != tc.want {
				t.Errorf("toVersion = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestIsUpgrade(t *testing.T) {
	tests := []struct {
		from, to string
		want     bool
		why      string
	}{
		{"0.51.0", "0.54.0", true, "ordinary forward move"},
		{"0.54.0", "0.51.0", false, "downgrade — specular#51"},
		{"0.54.0", "0.54.0", false, "already satisfied"},
		{"1.79.3", "1.81.0-dev", false, "stable must not adopt a prerelease — orbita#49"},
		{"1.80.0-dev", "1.81.0-dev", true, "prerelease may move within prereleases"},
		{"1.2.0-dev", "1.2.0", true, "prerelease to its release is forward"},
		{"1.9.0", "1.10.0", true, "numeric compare, not lexical: 10 > 9"},
		{"1.10.0", "1.9.0", false, "numeric compare, not lexical: 9 < 10"},
		{"v1.2.3", "v1.2.4", true, "leading v tolerated"},
		{"1.2", "1.2.1", true, "uneven component counts"},
		{"main-20260101", "1.2.3", false, "unparseable install"},
		{"1.2.3", "latest", false, "unparseable target"},
		{"", "1.2.3", true, "absent install version: apply, do not silently drop coverage"},
		{"", "1.2.3-dev", false, "absent install version still refuses a prerelease"},
	}

	for _, tc := range tests {
		t.Run(tc.why, func(t *testing.T) {
			if got := isUpgrade(tc.from, tc.to); got != tc.want {
				t.Errorf("isUpgrade(%q, %q) = %v, want %v — %s", tc.from, tc.to, got, tc.want, tc.why)
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
			if got := bestFix(tc.in); got != tc.want {
				t.Errorf("bestFix(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
