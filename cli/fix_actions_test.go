package main

import (
	"os"
	"path/filepath"
	"testing"
)

// fakeResolver returns scripted latest tag/sha per repo.
type fakeResolver map[string][2]string // repo -> {tag, sha}

func (f fakeResolver) latest(repo string) (tag, sha string, err error) {
	v, ok := f[repo]
	if !ok {
		return "", "", os.ErrNotExist
	}
	return v[0], v[1], nil
}

func writeWFPin(t *testing.T, root, name, body string) string {
	t.Helper()
	dir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParsePins(t *testing.T) {
	root := t.TempDir()
	p := writeWFPin(t, root, "ci.yml", `jobs:
  build:
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4
      - name: setup
        uses: actions/setup-go@v5
      - uses: owner/repo/sub-action@abc1234 # v1.2.3
      - run: echo not-a-uses
`)
	pins := parsePins(root, p)
	if len(pins) != 3 {
		t.Fatalf("expected 3 pins, got %d: %+v", len(pins), pins)
	}
	if pins[0].repo != "actions/checkout" || pins[0].currentVersion() != "v4" {
		t.Errorf("pin0 wrong: %+v cur=%q", pins[0], pins[0].currentVersion())
	}
	if pins[1].repo != "actions/setup-go" || pins[1].currentVersion() != "v5" {
		t.Errorf("pin1 (tag ref) wrong: %+v cur=%q", pins[1], pins[1].currentVersion())
	}
	if pins[2].full != "owner/repo/sub-action" || pins[2].repo != "owner/repo" || pins[2].currentVersion() != "v1.2.3" {
		t.Errorf("pin2 (subpath) wrong: %+v cur=%q", pins[2], pins[2].currentVersion())
	}
}

func TestRunActionsFix_RewritesOutdated(t *testing.T) {
	root := t.TempDir()
	p := writeWFPin(t, root, "ci.yml", `steps:
  - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v4.1.0
  - uses: actions/setup-go@v5.0.0
`)
	res := fakeResolver{
		"actions/checkout": {"v4.3.0", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		"actions/setup-go": {"v5.2.0", "cccccccccccccccccccccccccccccccccccccccc"},
	}
	applied, skipped, failed := runActionsFix(root, false, false, res)
	if applied != 2 || failed != 0 {
		t.Fatalf("applied=%d skipped=%d failed=%d, want applied=2", applied, skipped, failed)
	}
	got, _ := os.ReadFile(p)
	want := `steps:
  - uses: actions/checkout@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb # v4.3.0
  - uses: actions/setup-go@cccccccccccccccccccccccccccccccccccccccc # v5.2.0
`
	if string(got) != want {
		t.Errorf("rewrite wrong:\n%s", got)
	}
}

func TestRunActionsFix_SkipsUpToDateAndMajor(t *testing.T) {
	root := t.TempDir()
	writeWFPin(t, root, "ci.yml", `steps:
  - uses: actions/checkout@sha11111111111111111111111111111111111111 # v4.3.0
  - uses: actions/setup-go@sha22222222222222222222222222222222222222 # v5.0.0
`)
	res := fakeResolver{
		"actions/checkout": {"v4.3.0", "same"},     // already latest → skip
		"actions/setup-go": {"v6.0.0", "newmajor"}, // major jump → skip w/o flag
	}
	applied, skipped, failed := runActionsFix(root, true, false, res)
	if applied != 0 || failed != 0 || skipped != 2 {
		t.Errorf("want applied=0 skipped=2, got applied=%d skipped=%d failed=%d", applied, skipped, failed)
	}
	// With includeMajor, the major jump is applied (dry-run counts it).
	applied, _, _ = runActionsFix(root, true, true, res)
	if applied != 1 {
		t.Errorf("with --include-major want applied=1, got %d", applied)
	}
}

func TestVersionCompare(t *testing.T) {
	cases := []struct {
		a, b string
		less bool
	}{
		{"v4", "v4.3.0", true},
		{"v4.1.0", "v4.3.0", true},
		{"v4.3.0", "v4.3.0", false},
		{"v5.0.0", "v4.9.9", false},
		{"1.2.3", "1.2.4", true},
	}
	for _, c := range cases {
		if got := versionLess(c.a, c.b); got != c.less {
			t.Errorf("versionLess(%q,%q)=%v want %v", c.a, c.b, got, c.less)
		}
	}
	if majorComponent("v7.2.3") != 7 {
		t.Errorf("majorComponent v7.2.3 != 7")
	}
}

func TestIsSHA(t *testing.T) {
	if !isSHA("11bd71901bbe5b1630cea73d27597364c9af683a") {
		t.Error("40-hex should be a SHA")
	}
	if isSHA("v4") || isSHA("main") {
		t.Error("tags/branches are not SHAs")
	}
}
