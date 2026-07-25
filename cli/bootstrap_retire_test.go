package main

import (
	"strings"
	"testing"
)

// Reachability is no longer bundled into the release archive, so the records
// the old bootstrap wrote have to be retired rather than left behind.
//
// Leaving them is not an option: the record names a binary inside the install
// prefix, and once nox stops shipping that binary the path is wrong the moment
// the package manager cleans up. State would go on claiming an installed
// plugin that is not there, which is the "green while broken" shape this
// project keeps having to dig out — `doctor` says "binary missing" while
// `scan` says nothing and quietly runs without the plugin.
//
// So the record is removed and the operator is told how to get the plugin
// back. Deliberately actionable rather than silent: on Linux the bundled
// binary did work, so for those installs this is a real change in behaviour
// and it has to be visible.
func TestRetireBundledPlugins_RemovesRecordAndExplains(t *testing.T) {
	st := &State{}
	st.AddPlugin(&InstalledPlugin{
		Name:       "reachability",
		Version:    "bundled",
		BinaryPath: "/opt/homebrew/Cellar/nox/1.16.3/bin/nox-plugin-reachability",
		TrustLevel: "bundled",
	})

	notices := retireBundledPlugins(st)

	if st.FindPlugin("reachability") != nil {
		t.Error("the bundled record survived; state still claims a plugin nox no longer ships")
	}
	if len(notices) == 0 {
		t.Fatal("retiring a plugin silently removes functionality with no way to notice")
	}
	joined := strings.Join(notices, " ")
	if !strings.Contains(joined, "nox plugin install") {
		t.Errorf("notice does not tell the operator how to restore the plugin: %q", joined)
	}
	if !strings.Contains(joined, "reachability") {
		t.Errorf("notice does not name the plugin: %q", joined)
	}
}

// A plugin the operator installed themselves is not ours to retire, whatever
// its name. Only records the old bootstrap created carry trust level
// "bundled".
func TestRetireBundledPlugins_LeavesOperatorInstallAlone(t *testing.T) {
	st := &State{}
	st.AddPlugin(&InstalledPlugin{
		Name:       "reachability",
		Version:    "0.7.1",
		BinaryPath: "/home/me/.nox/cache/artifacts/extracted/ab/abc/nox-plugin-reachability",
		TrustLevel: "community",
	})

	if n := retireBundledPlugins(st); len(n) != 0 {
		t.Errorf("retiring touched an operator-installed plugin: %v", n)
	}
	got := st.FindPlugin("reachability")
	if got == nil || got.TrustLevel != "community" {
		t.Errorf("operator record was altered or removed: %+v", got)
	}
}

// Idempotent: a state with nothing to retire produces no notices, so the
// message appears once on upgrade and never again.
func TestRetireBundledPlugins_IsQuietWhenThereIsNothingToDo(t *testing.T) {
	st := &State{}
	if n := retireBundledPlugins(st); len(n) != 0 {
		t.Errorf("empty state produced notices: %v", n)
	}
	st.AddPlugin(&InstalledPlugin{Name: "taint-analysis", TrustLevel: "community"})
	if n := retireBundledPlugins(st); len(n) != 0 {
		t.Errorf("unrelated plugins produced notices: %v", n)
	}
}
