package main

import (
	"testing"
)

func mod(path, ver string) goModuleStatus {
	return goModuleStatus{Path: path, Version: ver}
}

func withUpdate(m goModuleStatus, to string) goModuleStatus {
	m.Update = &goModuleUpdate{Version: to}
	return m
}

// `nox fix` upgrades a dependency only when a VULN-001 finding names a
// fixed_in version — it is a security remediator, not a version bumper. That is
// deliberate, but it leaves outdated-but-not-vulnerable dependencies untouched
// forever, which is the job Dependabot was doing.
//
// --outdated is the opt-in currency pass. It is separate from the default
// behaviour on purpose: a security fix is something you want applied without
// argument, whereas routine version churn is a choice, and conflating the two
// would make `nox fix` unpredictable.
func TestPlanCurrencyUpgrades_UpgradesOutdatedDirectDeps(t *testing.T) {
	mods := []goModuleStatus{
		{Path: "example.com/main", Version: "", Main: true},
		withUpdate(mod("github.com/nox-hq/nox", "v1.17.0"), "v1.19.1"),
		mod("github.com/spf13/cobra", "v1.8.0"), // current, no Update field
	}

	plan := planCurrencyUpgrades(mods, false)

	if len(plan.actions) != 1 {
		t.Fatalf("expected exactly 1 upgrade, got %d: %+v", len(plan.actions), plan.actions)
	}
	a := plan.actions[0]
	if a.pkg != "github.com/nox-hq/nox" || a.fromVer != "v1.17.0" || a.toVersion != "v1.19.1" {
		t.Errorf("wrong upgrade planned: %+v", a)
	}
	if a.ecosystem != "go" {
		t.Errorf("ecosystem = %q, want go", a.ecosystem)
	}
	// The rule ID distinguishes currency upgrades from VULN-001 remediation in
	// the plan output, so an operator can see which is which at a glance.
	if a.ruleID == "VULN-001" {
		t.Error("a currency upgrade is attributed to VULN-001, which claims a vulnerability that was never found")
	}
}

// The main module always appears in `go list -m -u all` and must never be
// upgraded — `go get` on your own module is meaningless.
func TestPlanCurrencyUpgrades_SkipsTheMainModule(t *testing.T) {
	mods := []goModuleStatus{
		withUpdate(goModuleStatus{Path: "example.com/main", Version: "v0.1.0", Main: true}, "v0.2.0"),
	}
	if plan := planCurrencyUpgrades(mods, false); len(plan.actions) != 0 {
		t.Errorf("planned an upgrade of the main module: %+v", plan.actions)
	}
}

// Indirect dependencies are `go mod tidy`'s business. Bumping them directly
// writes explicit requirements into go.mod for things the project does not
// import, which is churn the operator did not ask for and has to unpick.
func TestPlanCurrencyUpgrades_SkipsIndirectDeps(t *testing.T) {
	m := withUpdate(mod("golang.org/x/sys", "v0.20.0"), "v0.24.0")
	m.Indirect = true

	if plan := planCurrencyUpgrades([]goModuleStatus{m}, false); len(plan.actions) != 0 {
		t.Errorf("planned an upgrade of an indirect dependency: %+v", plan.actions)
	}
}

// Same guard the security path uses: a major bump can break the build, so it
// needs --include-major. Counted rather than dropped silently, so the operator
// can see there is something waiting.
func TestPlanCurrencyUpgrades_HoldsMajorBumpsUnlessAsked(t *testing.T) {
	mods := []goModuleStatus{withUpdate(mod("github.com/foo/bar", "v1.2.0"), "v2.0.0")}

	plan := planCurrencyUpgrades(mods, false)
	if len(plan.actions) != 0 {
		t.Errorf("applied a major bump without --include-major: %+v", plan.actions)
	}
	if plan.majorSkipped != 1 {
		t.Errorf("major bump not reported as held back (majorSkipped=%d)", plan.majorSkipped)
	}

	if plan := planCurrencyUpgrades(mods, true); len(plan.actions) != 1 {
		t.Errorf("--include-major did not release the major bump: %+v", plan.actions)
	}
}

// A module with no Update field is already current. This is the common case and
// must produce no action at all — not a no-op `go get` that rewrites go.mod
// timestamps and makes an empty PR look like a real change.
func TestPlanCurrencyUpgrades_IgnoresCurrentModules(t *testing.T) {
	mods := []goModuleStatus{
		mod("github.com/a/b", "v1.0.0"),
		mod("github.com/c/d", "v2.3.4"),
	}
	if plan := planCurrencyUpgrades(mods, false); len(plan.actions) != 0 {
		t.Errorf("planned upgrades for already-current modules: %+v", plan.actions)
	}
}

// Defensive: `go list` can report an Update whose version is not actually
// newer (replace directives, retracted versions resolving oddly). Applying it
// would be a downgrade — the exact defect fixed for VULN-001 in #372, and it
// must not reappear on this path.
func TestPlanCurrencyUpgrades_NeverDowngrades(t *testing.T) {
	mods := []goModuleStatus{withUpdate(mod("github.com/foo/bar", "v1.5.0"), "v1.4.0")}
	if plan := planCurrencyUpgrades(mods, false); len(plan.actions) != 0 {
		t.Errorf("planned a downgrade: %+v", plan.actions)
	}
}

// Parsing the real shape `go list -m -u -json all` emits: a stream of
// concatenated JSON objects, not an array.
func TestParseGoListModules_ReadsConcatenatedJSONStream(t *testing.T) {
	stream := `{"Path":"example.com/main","Main":true}
{"Path":"github.com/nox-hq/nox","Version":"v1.17.0","Update":{"Path":"github.com/nox-hq/nox","Version":"v1.19.1"}}
{"Path":"golang.org/x/sys","Version":"v0.20.0","Indirect":true}
`
	mods, err := parseGoListModules([]byte(stream))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(mods) != 3 {
		t.Fatalf("expected 3 modules, got %d", len(mods))
	}
	if !mods[0].Main {
		t.Error("main module flag lost")
	}
	if mods[1].Update == nil || mods[1].Update.Version != "v1.19.1" {
		t.Errorf("update not parsed: %+v", mods[1])
	}
	if !mods[2].Indirect {
		t.Error("indirect flag lost")
	}
}
