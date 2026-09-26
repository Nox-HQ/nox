package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/fix"

	"github.com/nox-hq/nox/core/findings"
)

func TestPlanUpgrades_ProducesActionForGoVuln(t *testing.T) {
	in := []findings.Finding{{
		RuleID: "VULN-001",
		Metadata: map[string]string{
			"package":   "github.com/foo/bar",
			"version":   "1.2.3",
			"fixed_in":  "1.2.4",
			"ecosystem": "go",
		},
	}}
	plan := planUpgrades(in, false)
	if len(plan.actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(plan.actions))
	}
	a := plan.actions[0]
	if a.pkg != "github.com/foo/bar" || a.toVersion != "1.2.4" {
		t.Errorf("unexpected action: %+v", a)
	}
}

func TestPlanUpgrades_SkipsMajorBumpsByDefault(t *testing.T) {
	in := []findings.Finding{{
		RuleID: "VULN-001",
		Metadata: map[string]string{
			"package":   "github.com/foo/bar",
			"version":   "1.2.3",
			"fixed_in":  "2.0.0",
			"ecosystem": "go",
		},
	}}
	plan := planUpgrades(in, false)
	if len(plan.actions) != 0 {
		t.Errorf("expected major bump to be skipped by default, got %+v", plan.actions)
	}
	if plan.majorSkipped != 1 {
		t.Errorf("expected majorSkipped=1, got %d", plan.majorSkipped)
	}
}

func TestPlanUpgrades_IncludesMajorWhenFlagSet(t *testing.T) {
	in := []findings.Finding{{
		RuleID: "VULN-001",
		Metadata: map[string]string{
			"package":   "github.com/foo/bar",
			"version":   "1.2.3",
			"fixed_in":  "2.0.0",
			"ecosystem": "go",
		},
	}}
	plan := planUpgrades(in, true)
	if len(plan.actions) != 1 {
		t.Fatalf("expected 1 action with --include-major, got %d", len(plan.actions))
	}
}

func TestPlanUpgrades_NpmAction(t *testing.T) {
	in := []findings.Finding{{
		RuleID: "VULN-001",
		Metadata: map[string]string{
			"package":   "express",
			"fixed_in":  "4.19.0",
			"ecosystem": "npm",
		},
	}}
	plan := planUpgrades(in, false)
	if len(plan.actions) != 1 || plan.actions[0].action != "npm install" {
		t.Errorf("expected npm install action, got %+v", plan.actions)
	}
}

func TestPlanUpgrades_PyPIAction(t *testing.T) {
	in := []findings.Finding{{
		RuleID: "VULN-001",
		Metadata: map[string]string{
			"package":   "requests",
			"fixed_in":  "2.32.0",
			"ecosystem": "pypi",
		},
	}}
	plan := planUpgrades(in, false)
	if len(plan.actions) != 1 || plan.actions[0].action != "pip install" {
		t.Errorf("expected pip install action, got %+v", plan.actions)
	}
}

func TestPlanUpgrades_CargoAction(t *testing.T) {
	in := []findings.Finding{{
		RuleID: "VULN-001",
		Metadata: map[string]string{
			"package":   "openssl",
			"fixed_in":  "0.10.55",
			"ecosystem": "cargo",
		},
	}}
	plan := planUpgrades(in, false)
	if len(plan.actions) != 1 || plan.actions[0].action != "cargo update" {
		t.Errorf("expected cargo update action, got %+v", plan.actions)
	}
}

func TestPlanUpgrades_UnsupportedEcosystem(t *testing.T) {
	in := []findings.Finding{{
		RuleID: "VULN-001",
		Metadata: map[string]string{
			"package":   "example/lib",
			"fixed_in":  "1.0.0",
			"ecosystem": "Packagist",
		},
	}}
	plan := planUpgrades(in, false)
	if len(plan.actions) != 0 {
		t.Errorf("unsupported ecosystem must not produce an action, got %+v", plan.actions)
	}
	if plan.skipped != 1 {
		t.Errorf("expected skipped=1, got %d", plan.skipped)
	}
}

func TestPlanUpgrades_SkipsWithoutFixedIn(t *testing.T) {
	in := []findings.Finding{{
		RuleID:   "VULN-001",
		Metadata: map[string]string{"package": "github.com/foo/bar", "ecosystem": "go"},
	}}
	plan := planUpgrades(in, false)
	if len(plan.actions) != 0 {
		t.Error("findings without fixed_in metadata must not produce an action")
	}
}

func TestPlanUpgrades_DedupesByPackageVersion(t *testing.T) {
	in := []findings.Finding{
		{RuleID: "VULN-001", Metadata: map[string]string{"package": "p", "version": "1.0.0", "fixed_in": "1.0.1", "ecosystem": "go"}},
		{RuleID: "VULN-001", Metadata: map[string]string{"package": "p", "version": "1.0.0", "fixed_in": "1.0.1", "ecosystem": "go"}},
	}
	plan := planUpgrades(in, false)
	if len(plan.actions) != 1 {
		t.Errorf("duplicate findings should produce one action, got %d", len(plan.actions))
	}
}

func TestIsMajorBump(t *testing.T) {
	cases := []struct {
		from, to string
		want     bool
	}{
		{"1.2.3", "1.2.4", false},
		{"1.2.3", "2.0.0", true},
		{"v1.2.3", "v2.0.0", true},
		{"v1.2.3", "1.2.4", false},
		{"", "1.0.0", false},
	}
	for _, c := range cases {
		if got := fix.IsMajorBump(c.from, c.to); got != c.want {
			t.Errorf("isMajorBump(%q, %q) = %v, want %v", c.from, c.to, got, c.want)
		}
	}
}

// The findings a scan produces name the manifest the dependency was declared
// in — `apps/web/pnpm-lock.yaml`, not the repository root. Losing that on the
// way to the applier is what made `nox fix` run npm at the root of a monorepo
// and create a phantom root package.json, leaving the finding alive.
func TestPlanUpgrades_CarriesTheManifestPath(t *testing.T) {
	in := []findings.Finding{{
		RuleID:   "VULN-001",
		Location: findings.Location{FilePath: "apps/web/pnpm-lock.yaml"},
		Metadata: map[string]string{
			"package": "js-yaml", "version": "4.3.0", "fixed_in": "4.3.1", "ecosystem": "npm",
		},
	}}
	plan := planUpgrades(in, false)
	if len(plan.actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(plan.actions))
	}
	if got := plan.actions[0].manifest; got != "apps/web/pnpm-lock.yaml" {
		t.Errorf("manifest = %q, want the finding's own path", got)
	}
}

// Two workspaces depending on the same package at the same version are two
// upgrades, not one: fixing apps/web leaves site vulnerable.
func TestPlanUpgrades_SamePackageInTwoWorkspacesIsTwoActions(t *testing.T) {
	dep := map[string]string{
		"package": "astro", "version": "7.0.6", "fixed_in": "7.1.0", "ecosystem": "npm",
	}
	in := []findings.Finding{
		{RuleID: "VULN-001", Location: findings.Location{FilePath: "apps/web/package-lock.json"}, Metadata: dep},
		{RuleID: "VULN-001", Location: findings.Location{FilePath: "site/package-lock.json"}, Metadata: dep},
	}
	plan := planUpgrades(in, false)
	if len(plan.actions) != 2 {
		t.Fatalf("expected one action per workspace, got %d: %+v", len(plan.actions), plan.actions)
	}
}

// The same package in the same directory, reported by two advisories, is
// still one upgrade.
func TestPlanUpgrades_StillDedupesWithinOneManifest(t *testing.T) {
	dep := map[string]string{
		"package": "astro", "version": "7.0.6", "fixed_in": "7.1.0", "ecosystem": "npm",
	}
	in := []findings.Finding{
		{RuleID: "VULN-001", Location: findings.Location{FilePath: "site/package-lock.json"}, Metadata: dep},
		{RuleID: "VULN-001", Location: findings.Location{FilePath: "site/package-lock.json"}, Metadata: dep},
	}
	if plan := planUpgrades(in, false); len(plan.actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(plan.actions))
	}
}

func TestWorkdirFor_ResolvesToTheManifestDirectory(t *testing.T) {
	root := t.TempDir()
	touchFile(t, root, "apps/web/package.json")

	dir, err := workdirFor(root, upgradeAction{ecosystem: "npm", manifest: "apps/web/pnpm-lock.yaml"})
	if err != nil {
		t.Fatalf("workdirFor: %v", err)
	}
	if want := filepath.Join(root, "apps", "web"); dir != want {
		t.Errorf("dir = %q, want %q", dir, want)
	}
}

// The bug, stated as a test: a monorepo whose root holds no package.json must
// never have npm run in it. Refusing beats "helpfully" falling back to the
// root, which is how a phantom manifest gets committed.
func TestWorkdirFor_RefusesToRunWhereThereIsNoManifest(t *testing.T) {
	root := t.TempDir() // no package.json anywhere

	if dir, err := workdirFor(root, upgradeAction{ecosystem: "npm", manifest: "apps/web/pnpm-lock.yaml"}); err == nil {
		t.Fatalf("resolved to %q instead of refusing", dir)
	}
}

// A findings.json with no location is not a licence to guess: the root has to
// hold the manifest itself.
func TestWorkdirFor_WithoutALocationUsesTheRootOnlyIfItHasOne(t *testing.T) {
	root := t.TempDir()
	if _, err := workdirFor(root, upgradeAction{ecosystem: "go"}); err == nil {
		t.Fatal("accepted a root with no go.mod")
	}
	touchFile(t, root, "go.mod")
	if _, err := workdirFor(root, upgradeAction{ecosystem: "go"}); err != nil {
		t.Errorf("refused a root that does have go.mod: %v", err)
	}
}

// findings.json is an input file; a manifest path climbing out of the project
// would run a package manager somewhere nobody asked for.
func TestWorkdirFor_RefusesAPathOutsideTheRoot(t *testing.T) {
	root := t.TempDir()
	touchFile(t, root, "package.json")

	if dir, err := workdirFor(root, upgradeAction{ecosystem: "npm", manifest: "../../elsewhere/package-lock.json"}); err == nil {
		t.Fatalf("escaped the root to %q", dir)
	}
}

// npm is one ecosystem with four package managers. Running `npm install` in a
// pnpm workspace writes a package-lock.json beside the pnpm-lock.yaml and
// resolves nothing the workspace actually uses.
func TestNpmCommand_FollowsTheLockfile(t *testing.T) {
	for _, tc := range []struct {
		lockfile string
		extra    string
		want     string
	}{
		{"package-lock.json", "", "npm update"},
		{"pnpm-lock.yaml", "", "pnpm update"},
		{"yarn.lock", "", "yarn upgrade"},
		{"yarn.lock", ".yarnrc.yml", "yarn up"},
		{"bun.lockb", "", "bun update"},
		{"", "", "npm update"}, // package.json alone: npm is the baseline
	} {
		dir := t.TempDir()
		touchFile(t, dir, "package.json")
		if tc.lockfile != "" {
			touchFile(t, dir, tc.lockfile)
		}
		if tc.extra != "" {
			touchFile(t, dir, tc.extra)
		}

		name, args := npmCommand(dir, "js-yaml", "4.3.1")
		if got := name + " " + args[0]; got != tc.want {
			t.Errorf("with %s%s: got %q, want %q", tc.lockfile, " "+tc.extra, got, tc.want)
		}
		// npm update takes no version: it moves the package as far as the
		// ranges that pull it in allow, and the lockfile is checked after.
		want := "js-yaml@4.3.1"
		if name == "npm" {
			want = "js-yaml"
		}
		if last := args[len(args)-1]; last != want {
			t.Errorf("with %s: target = %q, want %q", tc.lockfile, last, want)
		}
	}
}

// npm install adds whatever it is given to package.json. Given a transitive
// package, it declared it as a new direct dependency — roady's app and website
// gained eleven that way from one `nox fix` — and given a devDependency, it
// moved it into dependencies. The manifest decides the verb.
func TestNpmCommand_TheManifestDecidesTheVerb(t *testing.T) {
	manifest := `{
  "dependencies": {"astro": "^7.1.6"},
  "devDependencies": {"vitest": "^3.0.0"},
  "optionalDependencies": {"fsevents": "^2.3.0"}
}`
	for _, tc := range []struct {
		pkg  string
		want string
	}{
		{"astro", "npm install astro@9.9.9"},
		{"vitest", "npm install --save-dev vitest@9.9.9"},
		{"fsevents", "npm install --save-optional fsevents@9.9.9"},
		{"fast-uri", "npm update fast-uri"}, // transitive: never declared
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(manifest), 0o600); err != nil {
			t.Fatal(err)
		}
		touchFile(t, dir, "package-lock.json")
		name, args := npmCommand(dir, tc.pkg, "9.9.9")
		if got := name + " " + strings.Join(args, " "); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.pkg, got, tc.want)
		}
	}
}

// npm update moves a transitive package only as far as its parents' ranges
// allow. If that stops short of the fixed version, the advisory is still there,
// and saying "applied" would be a false all-clear.
func TestNpmLockBelow_FindsCopiesStillShortOfTheFix(t *testing.T) {
	lock := `{"lockfileVersion": 3, "packages": {
  "": {"name": "app"},
  "node_modules/fast-uri": {"version": "3.1.6"},
  "node_modules/ajv/node_modules/fast-uri": {"version": "3.1.5"},
  "node_modules/not-fast-uri": {"version": "1.0.0"}
}}`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}
	below, err := npmLockBelow(dir, "fast-uri", "3.1.6")
	if err != nil {
		t.Fatal(err)
	}
	if len(below) != 1 || !strings.Contains(below[0], "node_modules/ajv/node_modules/fast-uri@3.1.5") {
		t.Errorf("want only the nested 3.1.5 copy; got %v", below)
	}
	if below, _ := npmLockBelow(dir, "not-fast-uri", "0.1.0"); len(below) != 0 {
		t.Errorf("a satisfied package reported short: %v", below)
	}
}

func touchFile(t *testing.T, root, rel string) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A package manager that exits 0 without rewriting anything — pnpm says
// "Already up to date" for a transitive dependency pinned by pnpm.overrides —
// used to be reported as "applied". The digest is what tells the difference.
func TestTreeDigest_MovesWithTheLockfile(t *testing.T) {
	dir := t.TempDir()
	touchFile(t, dir, "package.json")
	touchFile(t, dir, "pnpm-lock.yaml")

	before, ok := treeDigest(dir, "npm")
	if !ok {
		t.Fatal("npm reported unverifiable")
	}
	if after, _ := treeDigest(dir, "npm"); after != before {
		t.Error("digest changed without the tree changing")
	}

	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte("js-yaml@4.3.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if after, _ := treeDigest(dir, "npm"); after == before {
		t.Error("digest did not move when the lockfile did")
	}
}

// An ecosystem with no fixed file names cannot be checked this way, and must
// say so rather than silently reporting every upgrade as a no-op.
func TestTreeDigest_UnknownEcosystemIsUnverifiable(t *testing.T) {
	if _, ok := treeDigest(t.TempDir(), "nuget"); ok {
		t.Error("claimed to verify an ecosystem with no known manifests")
	}
}

// Upgrading browserslist moves baseline-browser-mapping, its dependency, so the
// separate upgrade for baseline-browser-mapping then rewrites nothing. That is
// not a failure — the lockfile already carries the fix — and counting it as one
// made a run that fixed every advisory exit non-zero.
func TestNpmAlreadySatisfied_WhenAnEarlierUpgradeMovedIt(t *testing.T) {
	dir := t.TempDir()
	lock := `{"lockfileVersion": 3, "packages": {
  "node_modules/baseline-browser-mapping": {"version": "2.11.0"}
}}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}
	a := upgradeAction{pkg: "baseline-browser-mapping", toVersion: "2.11.0", ecosystem: "npm"}
	if !alreadySatisfied(dir, a) {
		t.Error("every copy is at the fixed version; that is satisfied, not unchanged")
	}
	a.toVersion = "2.12.0"
	if alreadySatisfied(dir, a) {
		t.Error("a copy below the fix is not satisfied")
	}
	if alreadySatisfied(t.TempDir(), a) {
		t.Error("with no lockfile to read, nothing can be claimed")
	}
}
