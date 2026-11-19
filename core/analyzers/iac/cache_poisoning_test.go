package iac

import (
	"context"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
)

// IAC-507 spans two workflows: one on a trigger that runs in the base
// repository's cache scope saves a cache after checking out a fork's code, and
// a release workflow restores it. These tests write both files and scan them as
// one artifact set, since that is the only way the rule can be answered.

// seededHex returns a deterministic hex string, standing in for a lockfile hash
// or a cache suffix. The tests never hand-write token-like values.
func seededHex(seed int64, n int) string {
	r := rand.New(rand.NewSource(seed))
	const hex = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = hex[r.Intn(len(hex))]
	}
	return string(b)
}

const prtHeader = "name: pr\non:\n  pull_request_target:\n    types: [opened, synchronize]\n"

const pwnCheckout = `      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`

// writerWorkflow builds workflow A: header, then one job whose steps are the
// checkout of the fork and the given steps.
func writerWorkflow(header, jobExtra, checkout, steps string) string {
	return header + "jobs:\n  bench:\n    runs-on: ubuntu-latest\n" + jobExtra + "    steps:\n" + checkout + steps
}

func pnpmCacheSteps(key, restoreKeys string) string {
	s := "      - uses: actions/cache@v4\n        with:\n          path: ~/.local/share/pnpm/store\n          key: " + key + "\n"
	if restoreKeys != "" {
		s += "          restore-keys: |\n            " + restoreKeys + "\n"
	}
	return s + "      - run: pnpm install\n"
}

// releaseWorkflow builds workflow B.
func releaseWorkflow(on, perms, jobExtra, steps string) string {
	return "name: release\non:\n" + on + perms + "jobs:\n  release:\n    runs-on: ubuntu-latest\n" + jobExtra + "    steps:\n      - uses: actions/checkout@v4\n" + steps
}

const pushMain = "  push:\n    branches: [main]\n"
const oidc = "permissions:\n  contents: write\n  id-token: write\n"

func restorePnpm(key string) string {
	return "      - uses: actions/cache@v4\n        with:\n          path: ~/.local/share/pnpm/store\n          key: " + key + "\n      - run: pnpm install\n"
}

func TestIAC507CrossWorkflowCachePoisoning(t *testing.T) {
	h := seededHex(507, 40)
	storeKey := "pnpm-store-${{ runner.os }}-${{ hashFiles('pnpm-lock.yaml') }}"
	publish := "      - run: pnpm publish -r\n"

	cases := []struct {
		name      string
		a, b      string
		fires     bool
		wantInMsg []string
		wantConf  findings.Confidence
		wantBLine int
	}{
		{
			name:      "TanStack shape: prt pwn job saves the pnpm store, release restores it and publishes with OIDC",
			a:         writerWorkflow(prtHeader, "", pwnCheckout, pnpmCacheSteps(storeKey, "pnpm-store-${{ runner.os }}-")),
			b:         releaseWorkflow(pushMain, oidc, "", restorePnpm(storeKey)+publish),
			fires:     true,
			wantInMsg: []string{"a.yml:12", "pull_request_target", "id-token: write", "pnpm-store-"},
			wantConf:  findings.ConfidenceLow,
			wantBLine: 13,
		},
		{
			name:      "explicit cache-mode: write on the writing job makes the save certain",
			a:         writerWorkflow(prtHeader, "    cache-mode: write\n", pwnCheckout, pnpmCacheSteps(storeKey, "")),
			b:         releaseWorkflow(pushMain, oidc, "", restorePnpm(storeKey)+publish),
			fires:     true,
			wantInMsg: []string{"cache-mode: write"},
			wantConf:  findings.ConfidenceHigh,
		},
		{
			name:  "workflow-level cache-mode: write-only counts as a write",
			a:     writerWorkflow("cache-mode: write-only\n"+prtHeader, "", pwnCheckout, pnpmCacheSteps(storeKey, "")),
			b:     releaseWorkflow(pushMain, oidc, "", restorePnpm(storeKey)+publish),
			fires: true, wantConf: findings.ConfidenceHigh,
		},
		{
			name: "workflow_run writer",
			a: writerWorkflow("name: pr\non:\n  workflow_run:\n    workflows: [ci]\n", "",
				"      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.workflow_run.head_sha }}\n",
				pnpmCacheSteps(storeKey, "")),
			b:     releaseWorkflow(pushMain, oidc, "", restorePnpm(storeKey)+publish),
			fires: true, wantInMsg: []string{"workflow_run"},
		},
		{
			name: "issue_comment writer checking out refs/pull",
			a: writerWorkflow("name: pr\non:\n  issue_comment:\n    types: [created]\n", "",
				"      - uses: actions/checkout@v4\n        with:\n          ref: refs/pull/${{ github.event.issue.number }}/head\n",
				pnpmCacheSteps(storeKey, "")),
			b:     releaseWorkflow(pushMain, oidc, "", restorePnpm(storeKey)+publish),
			fires: true, wantInMsg: []string{"issue_comment"},
		},
		{
			name:  "restore-keys prefix in the release matches the writer's key",
			a:     writerWorkflow(prtHeader, "", pwnCheckout, pnpmCacheSteps("pnpm-store-linux-"+h, "")),
			b:     releaseWorkflow(pushMain, oidc, "", "      - uses: actions/cache/restore@v4\n        with:\n          path: x\n          key: nomatch-"+h+"\n          restore-keys: |\n            pnpm-store-\n"+publish),
			fires: true, wantInMsg: []string{"restore-keys"},
		},
		{
			name: "implicit saves: setup-node cache pnpm on both sides",
			a: writerWorkflow(prtHeader, "", pwnCheckout,
				"      - uses: actions/setup-node@v4\n        with:\n          node-version: 22\n          cache: pnpm\n"),
			b: releaseWorkflow(pushMain, "", "",
				"      - uses: actions/setup-node@v4\n        with:\n          cache: 'pnpm'\n      - run: npm publish\n"),
			fires: true, wantInMsg: []string{"setup-node", "pnpm"},
		},
		{
			name:  "publish through a secret only",
			a:     writerWorkflow(prtHeader, "", pwnCheckout, pnpmCacheSteps(storeKey, "")),
			b:     releaseWorkflow(pushMain, "", "", restorePnpm(storeKey)+"      - run: ./ship.sh\n        env:\n          TOKEN: ${{ secrets.NPM_TOKEN }}\n"),
			fires: true, wantInMsg: []string{"secrets.NPM_TOKEN"},
		},
		{
			name: "publish in a later job that needs the restoring job",
			a:    writerWorkflow(prtHeader, "", pwnCheckout, pnpmCacheSteps(storeKey, "")),
			b: "name: release\non:\n  push:\n    tags: ['v*']\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n" + restorePnpm(storeKey) +
				"  ship:\n    needs: [build]\n    runs-on: ubuntu-latest\n    permissions:\n      id-token: write\n    steps:\n      - run: twine upload dist/*\n",
			fires: true, wantInMsg: []string{"id-token: write"},
		},

		// Negatives.
		{
			name:  "writer on plain pull_request: its cache is scoped to the merge ref",
			a:     writerWorkflow("name: pr\non: pull_request\n", "", pwnCheckout, pnpmCacheSteps(storeKey, "")),
			b:     releaseWorkflow(pushMain, oidc, "", restorePnpm(storeKey)+publish),
			fires: false,
		},
		{
			name:  "release holds no publish capability",
			a:     writerWorkflow(prtHeader, "", pwnCheckout, pnpmCacheSteps(storeKey, "")),
			b:     releaseWorkflow(pushMain, "permissions:\n  contents: read\n", "", restorePnpm(storeKey)+"      - run: pnpm test\n"),
			fires: false,
		},
		{
			name:  "prt writer does not check out the pull request's code",
			a:     writerWorkflow(prtHeader, "", "      - uses: actions/checkout@v4\n", pnpmCacheSteps(storeKey, "")),
			b:     releaseWorkflow(pushMain, oidc, "", restorePnpm(storeKey)),
			fires: false,
		},
		{
			name:  "writer job sets cache-mode: read",
			a:     writerWorkflow(prtHeader, "    cache-mode: read\n", pwnCheckout, pnpmCacheSteps(storeKey, "")),
			b:     releaseWorkflow(pushMain, oidc, "", restorePnpm(storeKey)),
			fires: false,
		},
		{
			name:  "workflow-level cache-mode: none on the writer",
			a:     writerWorkflow("cache-mode: none\n"+prtHeader, "", pwnCheckout, pnpmCacheSteps(storeKey, "")),
			b:     releaseWorkflow(pushMain, oidc, "", restorePnpm(storeKey)),
			fires: false,
		},
		{
			name:  "writer only restores",
			a:     writerWorkflow(prtHeader, "", pwnCheckout, "      - uses: actions/cache/restore@v4\n        with:\n          path: x\n          key: "+storeKey+"\n"),
			b:     releaseWorkflow(pushMain, oidc, "", restorePnpm(storeKey)),
			fires: false,
		},
		{
			name:  "writer job is kept off prt by its if:",
			a:     writerWorkflow(prtHeader+"  push:\n", "    if: github.event_name == 'push'\n", pwnCheckout, pnpmCacheSteps(storeKey, "")),
			b:     releaseWorkflow(pushMain, oidc, "", restorePnpm(storeKey)),
			fires: false,
		},
		{
			name:  "keys cannot meet",
			a:     writerWorkflow(prtHeader, "", pwnCheckout, pnpmCacheSteps("pnpm-store-"+h, "")),
			b:     releaseWorkflow(pushMain, oidc, "", restorePnpm("go-build-${{ runner.os }}-"+h)),
			fires: false,
		},
		{
			name:  "keys that are only expressions say nothing",
			a:     writerWorkflow(prtHeader, "", pwnCheckout, pnpmCacheSteps("${{ matrix.key }}", "")),
			b:     releaseWorkflow(pushMain, oidc, "", restorePnpm("${{ inputs.key }}")),
			fires: false,
		},
		{
			name: "setup-node caches for different package managers",
			a: writerWorkflow(prtHeader, "", pwnCheckout,
				"      - uses: actions/setup-node@v4\n        with:\n          cache: npm\n"),
			b:     releaseWorkflow(pushMain, oidc, "", "      - uses: actions/setup-node@v4\n        with:\n          cache: pnpm\n"),
			fires: false,
		},
		{
			name:  "release only runs on pull_request",
			a:     writerWorkflow(prtHeader, "", pwnCheckout, pnpmCacheSteps(storeKey, "")),
			b:     releaseWorkflow("  pull_request:\n", oidc, "", restorePnpm(storeKey)+publish),
			fires: false,
		},
		{
			name:  "release job with cache-mode: none does not restore",
			a:     writerWorkflow(prtHeader, "", pwnCheckout, pnpmCacheSteps(storeKey, "")),
			b:     releaseWorkflow(pushMain, oidc, "    cache-mode: none\n", restorePnpm(storeKey)),
			fires: false,
		},
		{
			name: "restoring job is unrelated to the publishing job",
			a:    writerWorkflow(prtHeader, "", pwnCheckout, pnpmCacheSteps(storeKey, "")),
			b: "name: release\non:\n  push:\n    branches: [main]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n" + restorePnpm(storeKey) +
				"  ship:\n    runs-on: ubuntu-latest\n    permissions:\n      id-token: write\n    steps:\n      - run: npm publish\n",
			fires: false,
		},
		{
			name: "the head ref goes to an action that fetches no code",
			a: writerWorkflow(prtHeader, "",
				"      - uses: lewagon/wait-on-check-action@v1\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
				pnpmCacheSteps(storeKey, "")),
			b:     releaseWorkflow(pushMain, oidc, "", restorePnpm(storeKey)),
			fires: false,
		},
		{
			name: "actions/cache writer against a setup-node restore: different families",
			a:    writerWorkflow(prtHeader, "", pwnCheckout, pnpmCacheSteps("pnpm-store-"+h, "")),
			b: releaseWorkflow(pushMain, oidc, "",
				"      - uses: actions/setup-node@v4\n        with:\n          cache: pnpm\n"),
			fires: false,
		},
		{
			name:  "id-token: write alone is not a publish (Pages deploys and cloud logins take it)",
			a:     writerWorkflow(prtHeader, "", pwnCheckout, pnpmCacheSteps(storeKey, "")),
			b:     releaseWorkflow(pushMain, oidc, "", restorePnpm(storeKey)+"      - run: ./deploy-pages.sh\n"),
			fires: false,
		},
		{
			name: "writer job runs only for same-repository or merged pull requests (multi-line if:)",
			a: writerWorkflow(prtHeader, "    if: |\n      github.event_name == 'push' ||\n      (github.event_name == 'pull_request_target' && github.event.pull_request.head.repo.full_name == github.repository)\n",
				pwnCheckout, pnpmCacheSteps(storeKey, "")),
			b:     releaseWorkflow(pushMain, oidc, "", restorePnpm(storeKey)+publish),
			fires: false,
		},
		{
			name: "workflow_run job that runs only for this repository's own head",
			a: writerWorkflow("name: pr\non:\n  workflow_run:\n    workflows: [ci]\n", "    if: ${{ github.event.workflow_run.conclusion == 'success' && github.event.workflow_run.head_repository.full_name == github.repository }}\n",
				"      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.workflow_run.head_sha }}\n",
				pnpmCacheSteps(storeKey, "")),
			b:     releaseWorkflow(pushMain, oidc, "", restorePnpm(storeKey)+publish),
			fires: false,
		},
		{
			name:  "writer job runs only for dependabot",
			a:     writerWorkflow(prtHeader, "    if: github.actor == 'dependabot[bot]'\n", pwnCheckout, pnpmCacheSteps(storeKey, "")),
			b:     releaseWorkflow(pushMain, oidc, "", restorePnpm(storeKey)+publish),
			fires: false,
		},
		{
			name:  "a label check gates nothing: a maintainer labels a stranger's code",
			a:     writerWorkflow(prtHeader, "    if: contains(github.event.pull_request.labels.*.name, 'ok-to-test')\n", pwnCheckout, pnpmCacheSteps(storeKey, "")),
			b:     releaseWorkflow(pushMain, oidc, "", restorePnpm(storeKey)+publish),
			fires: true,
		},
		{
			name: "setup-go before v4 has no cache",
			a: writerWorkflow(prtHeader, "", pwnCheckout,
				"      - uses: actions/setup-go@v3\n        with:\n          go-version: 1.22\n"),
			b:     releaseWorkflow(pushMain, "", "", "      - uses: actions/setup-go@v5\n      - run: goreleaser release\n"),
			fires: false,
		},
		{
			name: "setup-go v5 caches by default on both sides",
			a: writerWorkflow(prtHeader, "", pwnCheckout,
				"      - uses: actions/setup-go@v5\n        with:\n          go-version: 1.22\n"),
			b:     releaseWorkflow(pushMain, "", "", "      - uses: actions/setup-go@v5\n      - run: goreleaser release --clean\n"),
			fires: true, wantInMsg: []string{"setup-go"},
		},
		{
			name:  "a path that contains npm/publish is not a publish",
			a:     writerWorkflow(prtHeader, "", pwnCheckout, pnpmCacheSteps(storeKey, "")),
			b:     releaseWorkflow(pushMain, "", "", restorePnpm(storeKey)+"      - run: node npm/publish.mjs --dry\n      - run: npm run publish-docs\n"),
			fires: false,
		},
		{
			name:  "the publish capability is only a comment",
			a:     writerWorkflow(prtHeader, "", pwnCheckout, pnpmCacheSteps(storeKey, "")),
			b:     releaseWorkflow(pushMain, "", "", restorePnpm(storeKey)+"      # npm publish later, with secrets.NPM_TOKEN\n"),
			fires: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs, _ := scanWorkflows(t, map[string]string{
				".github/workflows/a.yml":       tc.a,
				".github/workflows/release.yml": tc.b,
			})
			var got []findings.Finding
			for _, f := range fs.Findings() {
				if f.RuleID == "IAC-507" {
					got = append(got, f)
				}
			}
			if (len(got) > 0) != tc.fires {
				t.Fatalf("IAC-507 fired %d times, want fires=%v: %+v", len(got), tc.fires, got)
			}
			if !tc.fires {
				return
			}
			if len(got) != 1 {
				t.Fatalf("IAC-507 fired %d times, want once per restore step", len(got))
			}
			f := got[0]
			if f.Location.FilePath != ".github/workflows/release.yml" {
				t.Errorf("reported in %s, want the releasing workflow", f.Location.FilePath)
			}
			if !strings.Contains(f.Message, ".github/workflows/a.yml:") {
				t.Errorf("message does not name the writer's file:line: %s", f.Message)
			}
			for _, w := range tc.wantInMsg {
				if !strings.Contains(f.Message, w) {
					t.Errorf("message lacks %q: %s", w, f.Message)
				}
			}
			if tc.wantConf != "" && f.Confidence != tc.wantConf {
				t.Errorf("confidence %s, want %s", f.Confidence, tc.wantConf)
			}
			if tc.wantBLine != 0 && f.Location.StartLine != tc.wantBLine {
				t.Errorf("reported at line %d, want the restore step at %d", f.Location.StartLine, tc.wantBLine)
			}
		})
	}
}

// A single workflow that only restores has nothing to be poisoned by, and one
// that both saves and publishes is not a cross-workflow finding.
func TestIAC507NeedsTwoWorkflows(t *testing.T) {
	key := "pnpm-store-" + seededHex(5071, 12)
	for name, files := range map[string]map[string]string{
		"release alone": {".github/workflows/release.yml": releaseWorkflow(pushMain, oidc, "", restorePnpm(key))},
		"writer alone":  {".github/workflows/a.yml": writerWorkflow(prtHeader, "", pwnCheckout, pnpmCacheSteps(key, ""))},
		"one file does both": {".github/workflows/a.yml": "name: x\non:\n  pull_request_target:\n  push:\n" + oidc +
			"jobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n" + pwnCheckout + pnpmCacheSteps(key, "") + "      - run: pnpm publish\n"},
	} {
		t.Run(name, func(t *testing.T) {
			fs, _ := scanWorkflows(t, files)
			for _, f := range fs.Findings() {
				if f.RuleID == "IAC-507" {
					t.Errorf("IAC-507 fired: %+v", f)
				}
			}
		})
	}
}

func TestIAC507GlobsIntersect(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"pnpm-store-${{a}}-${{b}}", "pnpm-store-${{c}}-", true},
		{"pnpm-store-linux", "pnpm-store-${{c}}", true},
		{"pnpm-store-linux", "go-${{c}}", false},
		{"${{a}}", "go-build", true},
		{"a-${{a}}-z", "a-b-y", false},
		{"${{a}}abc${{a}}", "${{a}}xyz${{a}}", true},
	}
	for _, tc := range cases {
		if got := globsIntersect(parseKeyGlob(tc.a), parseKeyGlob(tc.b)); got != tc.want {
			t.Errorf("globsIntersect(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// scanWorkflows writes workflow files, directories included, and scans them as
// one artifact set.
func scanWorkflows(t *testing.T, files map[string]string) (fs *findings.FindingSet, _ struct{}) {
	t.Helper()
	dir := t.TempDir()
	var artifacts []discovery.Artifact
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		artifacts = append(artifacts, discovery.Artifact{Path: name, AbsPath: p})
	}
	fs, err := NewAnalyzer().ScanArtifacts(context.Background(), artifacts)
	if err != nil {
		t.Fatalf("ScanArtifacts: %v", err)
	}
	return fs, struct{}{}
}
