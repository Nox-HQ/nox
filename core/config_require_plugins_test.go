package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A plugin only contributes findings when it is declared, and declaration lives
// in a per-repository .nox.yaml — the wrong place for a fleet. A shared CI
// workflow installs the same plugin everywhere and pins its version centrally,
// but could not declare it, so every repository without its own .nox.yaml got
// reduced coverage silently (#403).
func TestLoadScanConfig_RequirePluginsEnv(t *testing.T) {
	cases := []struct {
		name string
		yaml string // "" = no .nox.yaml at all, the common fleet case
		env  string
		want []string
	}{
		{
			name: "no config and no env leaves it empty",
			want: nil,
		},
		{
			name: "env declares a plugin for a repo with no config",
			env:  "nox/taint-analysis",
			want: []string{"nox/taint-analysis"},
		},
		{
			// Additive, not replacing: a repo that lists its own plugins keeps
			// them, so setting the variable fleet-wide can only widen coverage.
			name: "env adds to what the repo declared",
			yaml: "version: 1\nplugins:\n  required:\n    - nox/taint-analysis\n",
			env:  "nox/reachability",
			want: []string{"nox/taint-analysis", "nox/reachability"},
		},
		{
			name: "a duplicate is not added twice",
			yaml: "version: 1\nplugins:\n  required:\n    - nox/taint-analysis\n",
			env:  "nox/taint-analysis",
			want: []string{"nox/taint-analysis"},
		},
		{
			name: "whitespace and empty entries are ignored",
			env:  " nox/taint-analysis , , nox/reachability ",
			want: []string{"nox/taint-analysis", "nox/reachability"},
		},
		{
			name: "an empty variable changes nothing",
			yaml: "version: 1\nplugins:\n  required:\n    - nox/taint-analysis\n",
			env:  "   ",
			want: []string{"nox/taint-analysis"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.yaml != "" {
				if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte(tc.yaml), 0o600); err != nil {
					t.Fatalf("write config: %v", err)
				}
			}
			t.Setenv(RequirePluginsEnv, tc.env)

			cfg, err := LoadScanConfig(dir)
			if err != nil {
				t.Fatalf("LoadScanConfig: %v", err)
			}
			got := cfg.Plugins.Required
			if len(got) != len(tc.want) {
				t.Fatalf("required = %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("required[%d] = %q, want %q (full: %v)", i, got[i], tc.want[i], got)
				}
			}
		})
	}
}

// The variable must not silently do nothing when the file is missing — that is
// precisely the case it exists for.
func TestLoadScanConfig_RequirePluginsEnv_NoConfigFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(RequirePluginsEnv, "nox/taint-analysis")

	cfg, err := LoadScanConfig(dir)
	if err != nil {
		t.Fatalf("LoadScanConfig: %v", err)
	}
	if len(cfg.Plugins.Required) != 1 || !strings.Contains(cfg.Plugins.Required[0], "taint") {
		t.Errorf("a repo with no .nox.yaml did not pick up the env declaration: %v", cfg.Plugins.Required)
	}
}
