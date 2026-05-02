package main

import (
	"testing"

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
		if got := isMajorBump(c.from, c.to); got != c.want {
			t.Errorf("isMajorBump(%q, %q) = %v, want %v", c.from, c.to, got, c.want)
		}
	}
}
