package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeResolver returns scripted latest tag/sha per repo. tagSHA resolves an
// arbitrary tag to a deterministic 40-hex SHA (its digits, 'a'-padded).
type fakeResolver map[string][2]string // repo -> {tag, sha}

func (f fakeResolver) latest(repo string) (tag, sha string, err error) {
	v, ok := f[repo]
	if !ok {
		return "", "", os.ErrNotExist
	}
	return v[0], v[1], nil
}

func (f fakeResolver) tagSHA(repo, tag string) (sha string, err error) {
	if _, ok := f[repo]; !ok {
		return "", os.ErrNotExist
	}
	// Deterministic, valid 40-hex SHA from the tag's digits, 'a'-padded.
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, tag)
	return (digits + strings.Repeat("a", 40))[:40], nil
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
  - uses: actions/checkout@1111111111111111111111111111111111111111 # v4.3.0
  - uses: actions/setup-go@2222222222222222222222222222222222222222 # v5.0.0
`)
	res := fakeResolver{
		"actions/checkout": {"v4.3.0", "1111111111111111111111111111111111111111"}, // SHA-pinned + latest → skip
		"actions/setup-go": {"v6.0.0", "3333333333333333333333333333333333333333"}, // major jump → skip w/o flag
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

func TestRunActionsFix_PinsMutableTags(t *testing.T) {
	root := t.TempDir()
	p := writeWFPin(t, root, "ci.yml", `steps:
  - uses: actions/checkout@v7
  - uses: actions/setup-node@v6
  - uses: octo/legacy@v2
`)
	res := fakeResolver{
		// same major as the pinned mutable tag → pin to the latest release SHA
		"actions/checkout":   {"v7.0.0", "1111111111111111111111111111111111111111"},
		"actions/setup-node": {"v6.4.0", "2222222222222222222222222222222222222222"},
		// newer major than the pin → hold the major, but SHA-pin @v2 in place
		"octo/legacy": {"v4.0.0", "9999999999999999999999999999999999999999"},
	}
	applied, skipped, failed := runActionsFix(root, false, false, res)
	if applied != 3 || failed != 0 {
		t.Fatalf("applied=%d skipped=%d failed=%d, want applied=3", applied, skipped, failed)
	}
	got, _ := os.ReadFile(p)
	// octo/legacy@v2 keeps the v2 comment but is now pinned to v2's own SHA.
	legacySHA, _ := res.tagSHA("octo/legacy", "v2")
	want := `steps:
  - uses: actions/checkout@1111111111111111111111111111111111111111 # v7.0.0
  - uses: actions/setup-node@2222222222222222222222222222222222222222 # v6.4.0
  - uses: octo/legacy@` + legacySHA + ` # v2
`
	if string(got) != want {
		t.Errorf("mutable-tag pinning wrong:\n%s", got)
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

// TestLatestTag_PrefersNewestTagOverStaleRelease guards against pinning an
// action BACKWARD.
//
// latestTag used to return the GitHub Release and consult tags only as a
// fallback for repos that publish no Releases. But an Action is consumed by
// TAG, not by Release object, so a repo that tags v1.0.1 without cutting a
// Release is already serving v1.0.1 to every workflow pinned to @v1.
//
// nox-hq/nox-remediate-action is exactly that shape, and the result was that
// `nox fix -actions` planned to rewrite @v1 (serving v1.0.1) to v1.0.0's
// commit — a silent downgrade, performed by the tool whose entire purpose is
// supply-chain pinning. The fixture below reproduces that repository.
func TestLatestTag_PrefersNewestTagOverStaleRelease(t *testing.T) {
	t.Parallel()

	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		switch {
		case strings.HasSuffix(r.URL.Path, "/releases/latest"):
			_, _ = io.WriteString(w, `{"tag_name":"v1.0.0"}`)
		case strings.HasSuffix(r.URL.Path, "/tags"):
			// Newest first, as GitHub returns them, including the moving major.
			_, _ = io.WriteString(w, `[{"name":"v1.0.1"},{"name":"v1.0.0"},{"name":"v1"}]`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	g := &githubResolver{client: srv.Client(), base: srv.URL}

	got, err := g.latestTag("nox-hq/nox-remediate-action")
	if err != nil {
		t.Fatalf("latestTag: %v", err)
	}
	if got != "v1.0.1" {
		t.Errorf("latestTag = %q, want v1.0.1 (the tag actually served; v1.0.0 is the stale Release)", got)
	}

	// Confirm the premise: the Release endpoint really was consulted, so this
	// passes because both sources were compared rather than because the
	// Release lookup silently failed.
	var sawRelease bool
	for _, h := range hits {
		if strings.HasSuffix(h, "/releases/latest") {
			sawRelease = true
		}
	}
	if !sawRelease {
		t.Error("premise broken: the Release endpoint was never queried")
	}
}

// TestLatestTag_TiePrefersSpecificTag pins the moving-vs-specific choice.
//
// v1 and v1.0.1 can denote the same commit, but only the specific tag still
// means that commit tomorrow — and it is what belongs in the `# version` pin
// comment.
func TestLatestTag_TiePrefersSpecificTag(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/releases/latest"):
			w.WriteHeader(http.StatusNotFound) // repo publishes no Releases
		case strings.HasSuffix(r.URL.Path, "/tags"):
			_, _ = io.WriteString(w, `[{"name":"v2"},{"name":"v2.0.0"}]`)
		}
	}))
	defer srv.Close()

	g := &githubResolver{client: srv.Client(), base: srv.URL}
	got, err := g.latestTag("some/action")
	if err != nil {
		t.Fatalf("latestTag: %v", err)
	}
	if got != "v2.0.0" {
		t.Errorf("latestTag = %q, want v2.0.0 (specific beats the moving v2 on a tie)", got)
	}
}

// TestLatestTag_FallsBackToReleaseWhenTagsUnavailable keeps a transient tags
// failure from erroring out a run that already has a usable answer.
func TestLatestTag_FallsBackToReleaseWhenTagsUnavailable(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/releases/latest") {
			_, _ = io.WriteString(w, `{"tag_name":"v3.1.0"}`)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	g := &githubResolver{client: srv.Client(), base: srv.URL}
	got, err := g.latestTag("some/action")
	if err != nil {
		t.Fatalf("latestTag should fall back to the Release, got error: %v", err)
	}
	if got != "v3.1.0" {
		t.Errorf("latestTag = %q, want v3.1.0", got)
	}
}

// A reusable workflow must NOT be rewritten to a digest.
//
// slsa-verifier resolves a trusted builder's identity from the ref, so pinning
// slsa-github-generator by SHA makes it unverifiable — upstream states the
// builders "MUST be referenced by tag ... contrary to the GitHub best practice
// for third-party actions ... but intentional due to limits in GitHub Actions".
// This tool pinned it anyway, and SLSA provenance vanished from six nox
// releases while every job but `final` reported success.
//
// The discriminator is the path: GitHub requires reusable workflows to live in
// .github/workflows/. An action published in a subdirectory
// (anchore/sbom-action/download-syft) is NOT a reusable workflow and must keep
// being pinned.
func TestIsReusableWorkflowRef(t *testing.T) {
	cases := []struct {
		full string
		want bool
	}{
		{"slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml", true},
		{"owner/repo/.github/workflows/build.yaml", true},
		{"anchore/sbom-action/download-syft", false},
		{"actions/checkout", false},
		{"github/codeql-action/upload-sarif", false},
		{"owner/repo/some/nested/action.yml", false},
	}
	for _, tc := range cases {
		if got := isReusableWorkflowRef(tc.full); got != tc.want {
			t.Errorf("isReusableWorkflowRef(%q) = %v, want %v", tc.full, got, tc.want)
		}
	}
}

// A prerelease must never be chosen as "latest".
//
// v2.1.0-rc.3 parsed to [2,1,0] — the -rc.3 was discarded — so it TIED v2.1.0,
// and the specificity tiebreak then counted its dots (4 vs 3) and declared the
// release candidate the more specific tag. `nox fix --actions` therefore
// replaced a stable @v2.1.0 with a release candidate's commit, in the workflow
// that produces this project's supply-chain attestations.
func TestReleaseTagRe_RejectsPrereleases(t *testing.T) {
	release := []string{"v1", "v1.2", "v1.2.3", "1.2.3"}
	pre := []string{
		"v2.1.0-rc.3", "v2.1.0-rc.0", "v1.0.0-beta", "v1.0.0-alpha.1",
		"v2.1.0.pre.rc.3", "v1.2.3+build.5",
	}
	for _, r := range release {
		if !releaseTagRe.MatchString(r) {
			t.Errorf("release tag %q was rejected", r)
		}
	}
	for _, p := range pre {
		if releaseTagRe.MatchString(p) {
			t.Errorf("prerelease tag %q was accepted as a release", p)
		}
	}
}

// The exact regression, end to end through the comparison used to pick latest:
// given both tags, the release must win.
func TestPreferTag_ReleaseBeatsItsOwnReleaseCandidate(t *testing.T) {
	if preferTag("v2.1.0", "v2.1.0-rc.3") {
		t.Error("v2.1.0-rc.3 was preferred over v2.1.0 — a release candidate must never outrank its release")
	}
}

// The exact regression, end to end: the line `nox fix --actions` rewrote on
// 2026-07-22, which removed SLSA provenance from six nox releases. The
// reusable workflow must come out byte-identical, while an ordinary action in
// the same file is still pinned — the skip must be surgical, not a blanket
// "leave anything with a path alone".
func TestRunActionsFix_LeavesReusableWorkflowsTagged(t *testing.T) {
	root := t.TempDir()
	p := writeWFPin(t, root, "slsa.yml", `jobs:
  provenance:
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0
  other:
    steps:
      - uses: anchore/sbom-action/download-syft@1111111111111111111111111111111111111111 # v0.24.0
`)
	res := fakeResolver{
		"slsa-framework/slsa-github-generator": {"v2.2.0", "dddddddddddddddddddddddddddddddddddddddd"},
		"anchore/sbom-action":                  {"v0.25.0", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"},
	}
	runActionsFix(root, false, false, res)

	got, _ := os.ReadFile(p)
	want := `jobs:
  provenance:
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0
  other:
    steps:
      - uses: anchore/sbom-action/download-syft@eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee # v0.25.0
`
	if string(got) != want {
		t.Errorf("reusable workflow was rewritten, or the sibling action was not:\n%s", got)
	}
}
