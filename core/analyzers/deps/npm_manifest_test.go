package deps

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox-core/vulnsource"
	"github.com/nox-hq/nox/core/discovery"
)

func TestResolveNPMSpec(t *testing.T) {
	tests := []struct {
		name, declared, spec string
		wantName, wantVer    string
		wantRange            bool
		wantReason           string
	}{
		{"exact", "axios", "0.21.1", "axios", "0.21.1", false, ""},
		{"exact with v", "axios", "v0.21.1", "axios", "0.21.1", false, ""},
		{"exact with =", "axios", "=0.21.1", "axios", "0.21.1", false, ""},
		{"exact prerelease", "x", "1.0.0-rc.1", "x", "1.0.0-rc.1", false, ""},
		{"exact with build metadata", "x", "1.0.0+build5", "x", "1.0.0", false, ""},
		{"caret", "axios", "^0.21.1", "axios", "0.21.1", true, ""},
		{"tilde", "minimist", "~1.2.0", "minimist", "1.2.0", true, ""},
		{"gte", "x", ">=1.4.0", "x", "1.4.0", true, ""},
		{"gte with space", "x", ">= 1.4.0", "x", "1.4.0", true, ""},
		{"gt", "x", ">1.4.0", "x", "1.4.0", true, ""},
		{"compound", "x", ">=1.2.0 <2.0.0", "x", "1.2.0", true, ""},
		{"union takes the first alternative", "x", "^1.0.0 || ^2.0.0", "x", "1.0.0", true, ""},
		{"hyphen", "x", "1.2.3 - 2.0.0", "x", "1.2.3", true, ""},
		{"partial major", "x", "^1", "x", "1.0.0", true, ""},
		{"partial minor", "x", "~1.2", "x", "1.2.0", true, ""},
		{"x range", "x", "1.x", "x", "1.0.0", true, ""},
		{"bare partial", "x", "1.2", "x", "1.2.0", true, ""},
		{"caret prerelease", "x", "^1.0.0-beta.2", "x", "1.0.0-beta.2", true, ""},
		{"npm alias", "my-axios", "npm:axios@0.21.1", "axios", "0.21.1", false, ""},
		{"npm alias scoped range", "a", "npm:@scope/pkg@^2.1.0", "@scope/pkg", "2.1.0", true, ""},
		{"npm alias without version", "a", "npm:axios", "", "", false, "npm alias without a version"},
		{"star", "x", "*", "", "", false, "no version constraint"},
		{"empty", "x", "", "", "", false, "no version constraint"},
		{"latest", "x", "latest", "", "", false, "no version constraint"},
		{"dist-tag", "x", "next", "", "", false, "dist-tag"},
		{"upper bound only", "x", "<2.0.0", "", "", false, "range has no lower bound"},
		{"wildcard major", "x", "*.1.2", "", "", false, "range has no lower bound"},
		{"workspace", "x", "workspace:*", "", "", false, "not a registry version"},
		{"workspace caret", "x", "workspace:^1.0.0", "", "", false, "not a registry version"},
		{"git https", "x", "git+https://github.com/a/b.git#v1", "", "", false, "not a registry version"},
		{"github shorthand", "x", "github:a/b", "", "", false, "not a registry version"},
		{"owner repo shorthand", "x", "a/b#main", "", "", false, "not a registry version"},
		{"tarball url", "x", "https://example.com/x-1.0.0.tgz", "", "", false, "not a registry version"},
		{"file", "x", "file:../x", "", "", false, "not a registry version"},
		{"link", "x", "link:../x", "", "", false, "not a registry version"},
		{"relative path", "x", "../x", "", "", false, "not a registry version"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			name, ver, isRange, reason := resolveNPMSpec(tc.declared, tc.spec)
			if name != tc.wantName || ver != tc.wantVer || isRange != tc.wantRange || reason != tc.wantReason {
				t.Errorf("resolveNPMSpec(%q, %q) = (%q, %q, range=%v, %q), want (%q, %q, range=%v, %q)",
					tc.declared, tc.spec, name, ver, isRange, reason,
					tc.wantName, tc.wantVer, tc.wantRange, tc.wantReason)
			}
		})
	}
}

func TestParsePackageJSONManifest(t *testing.T) {
	content := `{
	  "dependencies": {"express": "4.17.1", "axios": "^0.21.1", "internal": "workspace:*"},
	  "devDependencies": {"minimist": "~1.2.0", "express": "1.0.0"},
	  "optionalDependencies": {"fsevents": "2.3.2"},
	  "peerDependencies": {"react": ">=16"}
	}`
	pkgs, unresolved, err := parsePackageJSONManifest([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	want := []Package{
		{Name: "axios", Version: "0.21.1", Ecosystem: "npm", Spec: "^0.21.1"},
		{Name: "express", Version: "4.17.1", Ecosystem: "npm"}, // dependencies wins over devDependencies
		{Name: "fsevents", Version: "2.3.2", Ecosystem: "npm"},
		{Name: "minimist", Version: "1.2.0", Ecosystem: "npm", Spec: "~1.2.0"},
	}
	if !reflect.DeepEqual(pkgs, want) {
		t.Errorf("packages = %+v\nwant       %+v", pkgs, want)
	}
	if len(unresolved) != 1 || unresolved[0].Name != "internal" {
		t.Errorf("unresolved = %+v, want only internal", unresolved)
	}
}

func TestParsePackageJSONManifest_Malformed(t *testing.T) {
	if _, _, err := parsePackageJSONManifest([]byte(`{"dependencies":`)); err == nil {
		t.Error("malformed package.json parsed without error")
	}
	pkgs, unresolved, err := parsePackageJSONManifest([]byte(`{"name":"x"}`))
	if err != nil || len(pkgs)+len(unresolved) != 0 {
		t.Errorf("manifest without dependencies = %v %v %v", pkgs, unresolved, err)
	}
}

var lockfileTypes = map[string]bool{"package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true}

// writeTree writes files under a temp dir and returns the discovery artifacts.
func writeTree(t *testing.T, files map[string]string) []discovery.Artifact {
	t.Helper()
	root := t.TempDir()
	var arts []discovery.Artifact
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		typ := discovery.Config
		if lockfileTypes[filepath.Base(rel)] {
			typ = discovery.Lockfile
		}
		arts = append(arts, discovery.Artifact{Path: rel, AbsPath: p, Type: typ})
	}
	return arts
}

func scanOffline(t *testing.T, arts []discovery.Artifact) (*PackageInventory, *degrade.Degradations) {
	t.Helper()
	d := &degrade.Degradations{}
	a := NewAnalyzer(WithOSVDisabled(), WithDegradations(d))
	inv, _, err := a.ScanArtifacts(context.Background(), arts)
	if err != nil {
		t.Fatal(err)
	}
	return inv, d
}

const axiosManifest = `{"dependencies":{"axios":"0.21.1","express":"4.17.1"}}`

func TestScanArtifacts_ManifestWithoutLockfileIsInventoried(t *testing.T) {
	inv, d := scanOffline(t, writeTree(t, map[string]string{"package.json": axiosManifest}))
	got := map[string]string{}
	for _, p := range inv.Packages() {
		got[p.Name] = p.Version
	}
	if !reflect.DeepEqual(got, map[string]string{"axios": "0.21.1", "express": "4.17.1"}) {
		t.Errorf("inventory = %v", got)
	}
	items := d.Items()
	if len(items) != 1 || items[0].Kind != degrade.Lockfile || items[0].Blocks() {
		t.Fatalf("want one advisory lockfile degradation, got %+v", items)
	}
	if !strings.Contains(items[0].Impact, "commit a lockfile") {
		t.Errorf("impact does not recommend a lockfile: %q", items[0].Impact)
	}
}

// A lockfile stays authoritative: its version wins and nothing is counted twice.
func TestScanArtifacts_LockfileWinsAndIsNotDoubleCounted(t *testing.T) {
	arts := writeTree(t, map[string]string{
		"package.json": `{"dependencies":{"axios":"^0.21.0","express":"4.17.1"}}`,
		"package-lock.json": `{"packages":{"":{"name":"app"},` +
			`"node_modules/axios":{"version":"0.21.4"},"node_modules/express":{"version":"4.17.1"},` +
			`"node_modules/follow-redirects":{"version":"1.14.0"}}}`,
	})
	inv, d := scanOffline(t, arts)
	count := map[string]int{}
	ver := map[string]string{}
	for _, p := range inv.Packages() {
		count[p.Name]++
		ver[p.Name] = p.Version
	}
	for n, c := range count {
		if c != 1 {
			t.Errorf("%s counted %d times", n, c)
		}
	}
	if ver["axios"] != "0.21.4" {
		t.Errorf("axios = %s, want the lockfile's 0.21.4", ver["axios"])
	}
	if len(count) != 3 {
		t.Errorf("inventory = %v, want 3 packages", count)
	}
	if d.Len() != 0 {
		t.Errorf("a governed manifest must not degrade the scan: %+v", d.Items())
	}
}

// A workspace root's lockfile governs member manifests below it, and a manifest
// under node_modules is a dependency's own, never the project's.
func TestScanArtifacts_WorkspaceMembersAndNodeModules(t *testing.T) {
	arts := writeTree(t, map[string]string{
		"package-lock.json":                        `{"packages":{"node_modules/axios":{"version":"1.6.0"}}}`,
		"packages/web/package.json":                `{"dependencies":{"axios":"^1.0.0"}}`,
		"node_modules/leftpad/package.json":        `{"dependencies":{"lodash":"4.17.4"}}`,
		"packages/web/node_modules/x/package.json": `{"dependencies":{"minimist":"0.0.8"}}`,
	})
	inv, d := scanOffline(t, arts)
	if n := len(inv.Packages()); n != 1 {
		t.Errorf("inventory = %+v, want only the lockfile's axios", inv.Packages())
	}
	if d.Len() != 0 {
		t.Errorf("unexpected degradations: %+v", d.Items())
	}
}

// An unrelated lockfile elsewhere does not suppress the manifest.
func TestScanArtifacts_UnrelatedLockfileDoesNotGovern(t *testing.T) {
	arts := writeTree(t, map[string]string{
		"a/package-lock.json": `{"packages":{"node_modules/axios":{"version":"1.6.0"}}}`,
		"b/package.json":      `{"dependencies":{"axios":"0.21.1"}}`,
	})
	inv, _ := scanOffline(t, arts)
	if n := len(inv.Packages()); n != 2 {
		t.Errorf("inventory = %+v, want a's lock entry and b's manifest entry", inv.Packages())
	}
}

func TestScanArtifacts_UnresolvedSpecsAreReportedNotGuessed(t *testing.T) {
	arts := writeTree(t, map[string]string{
		"package.json": `{"dependencies":{"internal":"workspace:*","forked":"github:a/b"}}`,
	})
	inv, d := scanOffline(t, arts)
	if n := len(inv.Packages()); n != 0 {
		t.Errorf("inventory = %+v, want none", inv.Packages())
	}
	items := d.Items()
	if len(items) != 1 {
		t.Fatalf("degradations = %+v", items)
	}
	for _, want := range []string{"internal@workspace:*", "forked@github:a/b", "NOT checked"} {
		if !strings.Contains(items[0].Impact, want) {
			t.Errorf("impact %q lacks %q", items[0].Impact, want)
		}
	}
}

// A range finding says it was checked at the lower bound, and is medium
// confidence; an exact pin is neither annotated nor demoted.
func TestScanArtifacts_RangeFindingStatesItsBasis(t *testing.T) {
	src := &stubSource{name: "stub", records: map[string][]vulnsource.Record{
		"axios":   {{ID: "STUB-1", Summary: "SSRF"}},
		"express": {{ID: "STUB-2", Summary: "open redirect"}},
	}}
	arts := writeTree(t, map[string]string{
		"package.json": `{"dependencies":{"axios":"^0.21.1","express":"4.17.1"}}`,
	})
	a := NewAnalyzer(WithSource(src), WithDegradations(&degrade.Degradations{}))
	_, fs, err := a.ScanArtifacts(context.Background(), arts)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, f := range fs.Findings() {
		if f.RuleID != "VULN-001" {
			continue
		}
		seen++
		switch f.Metadata["package"] {
		case "axios":
			if f.Metadata["declared_spec"] != "^0.21.1" || f.Metadata["version_source"] != "manifest_range_lower_bound" ||
				!strings.Contains(f.Message, "lower bound") || f.Confidence != "medium" {
				t.Errorf("range finding not annotated: %+v", f)
			}
		case "express":
			if f.Metadata["declared_spec"] != "" || f.Confidence != "high" {
				t.Errorf("exact pin wrongly annotated: %+v", f)
			}
		}
	}
	if seen != 2 {
		t.Errorf("VULN-001 findings = %d, want 2", seen)
	}
}
