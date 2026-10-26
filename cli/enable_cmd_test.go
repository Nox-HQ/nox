package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core"
)

func TestAddRequiredPlugins_PreservesTextAndShapes(t *testing.T) {
	cases := []struct{ name, in, wantHas string }{
		{"empty", "", "plugins:\n  required:\n    - nox/api-abuse\n"},
		{"no plugins key", "# keep me\nscan:\n  x: 1\n", "# keep me\nscan:\n  x: 1\nplugins:\n  required:\n    - nox/api-abuse\n"},
		{"existing list", "plugins:\n  required:\n    - nox/other@>=1\n# tail\n", "    - nox/other@>=1\n    - nox/api-abuse\n# tail\n"},
		{"empty flow list", "plugins:\n  required: []\nscan:\n  a: 1\n", "  required:\n    - nox/api-abuse\nscan:"},
		{"plugins without required", "plugins:\n  dir: x\n", "plugins:\n  required:\n    - nox/api-abuse\n  dir: x\n"},
	}
	for _, c := range cases {
		out, added, err := addRequiredPlugins(c.in, []string{"nox/api-abuse"})
		if err != nil || len(added) != 1 {
			t.Fatalf("%s: err=%v added=%v", c.name, err, added)
		}
		if !strings.Contains(out, c.wantHas) {
			t.Errorf("%s: want %q in\n%s", c.name, c.wantHas, out)
		}
		if !projectEnablesPlugin(parseRequired(out), "nox/api-abuse") {
			t.Errorf("%s: scan loader does not see it:\n%s", c.name, out)
		}
	}
	if _, added, _ := addRequiredPlugins("plugins:\n  required:\n    - nox/api-abuse@>=1\n", []string{"nox/api-abuse"}); len(added) != 0 {
		t.Errorf("already enabled entry was added again")
	}
	if _, _, err := addRequiredPlugins("plugins: {required: [a]}\n", []string{"x"}); err == nil {
		t.Errorf("flow-style plugins must be refused, not guessed at")
	}
}

func TestEnable_ByCapabilityWritesConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("NOX_HOME", home)
	seedPlugins(t, home, "nox/api-abuse", "nox/attack-surface", "nox/dast", "nox/container")
	proj := t.TempDir()
	t.Chdir(proj)

	if code := runEnable([]string{"api-abuse"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	cfg, err := core.LoadScanConfig(proj)
	if err != nil {
		t.Fatal(err)
	}
	if !projectEnablesPlugin(cfg.Plugins.Required, "nox/api-abuse") || projectEnablesPlugin(cfg.Plugins.Required, "nox/attack-surface") {
		t.Errorf("required = %v", cfg.Plugins.Required)
	}
	// all: only installed optional checks, never a live or covered one.
	if code := runEnable([]string{"all"}); code != 0 {
		t.Fatalf("all exit %d", code)
	}
	cfg, _ = core.LoadScanConfig(proj)
	for _, n := range []string{"nox/dast", "nox/container"} {
		if projectEnablesPlugin(cfg.Plugins.Required, n) {
			t.Errorf("all enabled %s", n)
		}
	}
	if !projectEnablesPlugin(cfg.Plugins.Required, "nox/attack-surface") {
		t.Errorf("all did not enable attack-surface: %v", cfg.Plugins.Required)
	}
	b, _ := os.ReadFile(filepath.Join(proj, ".nox.yaml"))
	if strings.Count(string(b), "nox/api-abuse") != 1 {
		t.Errorf("duplicate entry:\n%s", b)
	}
}

func TestEnable_Refusals(t *testing.T) {
	home := t.TempDir()
	t.Setenv("NOX_HOME", home)
	seedPlugins(t, home, "nox/dast")
	t.Chdir(t.TempDir())
	for _, a := range []string{"nope", "api-abuse", "nox/dast"} {
		if code := runEnable([]string{a}); code != 2 {
			t.Errorf("%s: exit %d, want 2", a, code)
		}
	}
	if _, err := os.Stat(".nox.yaml"); err == nil {
		t.Errorf("a refused enable created .nox.yaml")
	}
}
