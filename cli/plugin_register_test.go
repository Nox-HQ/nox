package main

import (
	"context"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox/registry"
)

// Plugin registration used to be all-or-nothing per phase: runPluginBinaries
// registered every binary up front and returned an error the moment one was
// rejected, so a single gated plugin took the whole batch down with it.
//
// Requiring all ~20 installed plugins on nox's own repo hit exactly that —
// nox/api-abuse declares needs_confirmation, the default policy does not allow
// it, and the rejection aborted registration for all 20. The scan then fell
// back to built-in findings only, having silently run none of the plugins the
// project declared as required. One plugin's policy gate must not disable
// every other plugin's detection.
//
// A rejected plugin is now degraded individually (the same treatment an
// uninstalled or integrity-failed plugin already gets) and the rest still run.
func TestRunPluginBinaries_OneBadPluginDegradesRatherThanAbortingTheBatch(t *testing.T) {
	// /bin/echo is executable but is not a plugin: it exits immediately without
	// completing the handshake, so registering it fails the same way a policy
	// rejection does — from the caller's side, a registration error.
	bins := []installedPlugin{
		{name: "nox/not-a-plugin", path: "/bin/echo", track: registry.Track("core-analysis")},
	}

	out, err := runPluginBinaries(context.Background(), t.TempDir(), bins, nil, nil, false)
	if err != nil {
		t.Fatalf("a plugin that fails to register must not abort the scan, got error: %v", err)
	}
	if out == nil {
		t.Fatal("expected output carrying a degradation, got nil")
	}

	var reported bool
	for _, d := range out.Degradations {
		if d.Kind == degrade.Plugin && strings.Contains(d.Detail, "not-a-plugin") {
			reported = true
		}
	}
	if !reported {
		t.Errorf("a plugin that failed to register was not reported as a degradation: %+v", out.Degradations)
	}
}
