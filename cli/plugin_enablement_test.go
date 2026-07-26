package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Installing a plugin does not make it run — `plugins.required` in the
// project's .nox.yaml decides that, and deliberately so: nox's first design
// constraint is that the same inputs produce the same outputs with no hidden
// state, and a globally-installed plugin that ran automatically would make
// findings depend on which plugins happen to be on the machine.
//
// The cost of that correct design is a quiet dead end: install succeeds, `nox
// plugin list` shows the plugin, the scan reports nothing, and the natural
// reading is "the plugin found nothing" rather than "the plugin never ran".
// These helpers are what the CLI uses to close that gap. See #376.
func TestProjectEnablesPlugin(t *testing.T) {
	cases := []struct {
		name     string
		required []string
		plugin   string
		want     bool
	}{
		{
			name:     "bare name listed",
			required: []string{"nox/reachability"},
			plugin:   "nox/reachability",
			want:     true,
		},
		{
			// The documented form in the README carries a constraint, so a
			// naive string compare reports the plugin inactive when it is
			// listed — the exact case the feature exists to report on.
			name:     "listed with a version constraint",
			required: []string{"nox/reachability@>=0.5"},
			plugin:   "nox/reachability",
			want:     true,
		},
		{
			name:     "pinned to an exact version",
			required: []string{"nox/grc@0.5.0"},
			plugin:   "nox/grc",
			want:     true,
		},
		{
			name:     "not listed at all",
			required: []string{"nox/ai-eval", "nox/taint-analysis"},
			plugin:   "nox/reachability",
			want:     false,
		},
		{
			name:     "empty config enables nothing",
			required: nil,
			plugin:   "nox/reachability",
			want:     false,
		},
		{
			// Prefix collisions must not read as a match: a project requiring
			// nox/reachability-extra has not enabled nox/reachability.
			name:     "a longer name sharing a prefix is not a match",
			required: []string{"nox/reachability-extra"},
			plugin:   "nox/reachability",
			want:     false,
		},
		{
			name:     "surrounding whitespace is tolerated",
			required: []string{"  nox/reachability  "},
			plugin:   "nox/reachability",
			want:     true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := projectEnablesPlugin(tc.required, tc.plugin); got != tc.want {
				t.Errorf("projectEnablesPlugin(%q, %q) = %v, want %v",
					tc.required, tc.plugin, got, tc.want)
			}
		})
	}
}

// The hint has one job: make the next step copy-pasteable. A message that says
// "add it to your config" without saying what to write leaves the user in the
// same place.
func TestEnablePluginHint_IsCopyPasteable(t *testing.T) {
	got := enablePluginHint("nox/reachability")

	for _, want := range []string{".nox.yaml", "plugins:", "required:", "nox/reachability"} {
		if !strings.Contains(got, want) {
			t.Errorf("hint is missing %q, so it cannot be acted on directly:\n%s", want, got)
		}
	}

	// The snippet must be valid YAML shape: `required:` is a list, so the
	// plugin has to appear as an item, not a bare line.
	if !strings.Contains(got, "- nox/reachability") {
		t.Errorf("plugin is not rendered as a YAML list item; pasting this produces invalid config:\n%s", got)
	}
}

// The hint names the specific plugin just installed, not a placeholder.
func TestEnablePluginHint_NamesThePluginInstalled(t *testing.T) {
	got := enablePluginHint("nox/taint-analysis")
	if strings.Contains(got, "reachability") {
		t.Errorf("hint mentions an unrelated plugin:\n%s", got)
	}
	if !strings.Contains(got, "nox/taint-analysis") {
		t.Errorf("hint does not name the installed plugin:\n%s", got)
	}
}

func seedPlugins(t *testing.T, home string, names ...string) {
	t.Helper()
	st := &State{}
	for _, n := range names {
		st.AddPlugin(&InstalledPlugin{
			Name: n, Version: "0.9.0", TrustLevel: "community", InstalledAt: time.Now(),
		})
	}
	if err := SaveState(filepath.Join(home, "state.json"), st); err != nil {
		t.Fatalf("save state: %v", err)
	}
}

// The whole point of the ACTIVE column: in a directory with no .nox.yaml,
// nothing an operator has installed will run, and the listing has to say so.
// Before this, all four columns described a plugin that was about to do
// nothing, and read as confirmation that it was set up.
func TestPluginList_ReportsInstalledPluginsAsInactiveWithoutConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("NOX_HOME", home)
	seedPlugins(t, home, "nox/reachability")
	t.Chdir(t.TempDir()) // a project with no .nox.yaml

	out := captureStdout(t, func() {
		if code := runPlugin([]string{"list"}); code != 0 {
			t.Fatalf("plugin list exited %d", code)
		}
	})

	if !strings.Contains(out, "ACTIVE") {
		t.Errorf("listing has no ACTIVE column, so it cannot distinguish "+
			"'installed' from 'will actually run here':\n%s", out)
	}
	if !strings.Contains(out, "will not run in this directory") {
		t.Errorf("no explanation that the installed plugin is inactive here:\n%s", out)
	}
}

// The converse: once the project requires it, the same plugin must read as
// active — otherwise the column is noise that says "no" forever.
func TestPluginList_ReportsActiveWhenProjectRequiresIt(t *testing.T) {
	home := t.TempDir()
	t.Setenv("NOX_HOME", home)
	seedPlugins(t, home, "nox/reachability")

	proj := t.TempDir()
	// Written with a version constraint, the form the README documents.
	cfg := "plugins:\n  required:\n    - nox/reachability@>=0.5\n"
	if err := os.WriteFile(filepath.Join(proj, ".nox.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Chdir(proj)

	out := captureStdout(t, func() {
		if code := runPlugin([]string{"list"}); code != 0 {
			t.Fatalf("plugin list exited %d", code)
		}
	})

	if strings.Contains(out, "will not run in this directory") {
		t.Errorf("a plugin listed in plugins.required was reported as inactive:\n%s", out)
	}
	if !strings.Contains(out, "yes") {
		t.Errorf("required plugin is not marked active:\n%s", out)
	}
}
