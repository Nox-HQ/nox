package main

import (
	"context"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/degrade"
)

// The heavy path (registering a real plugin binary, gRPC invocation, proto
// conversion) is covered by plugin/host_test.go and plugin/convert_test.go.
// These tests cover this package's orchestration branches.

func TestRunScanPlugins_NoRequired_NoOp(t *testing.T) {
	out, err := runScanPlugins(context.Background(), t.TempDir(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != nil {
		t.Fatalf("expected nil output for empty required, got %+v", out)
	}
}

func TestRunPluginBinaries_NoBinaries_NoOp(t *testing.T) {
	out, err := runPluginBinaries(context.Background(), t.TempDir(), nil, nil, nil, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != nil {
		t.Fatalf("expected nil output for no binaries, got %+v", out)
	}
}

func TestRunScanPlugins_UninstalledRequired_IsReported(t *testing.T) {
	// A required plugin that isn't installed must not abort the scan — but it
	// must not vanish either.
	//
	// This previously asserted a nil output, i.e. that the plugin was silently
	// skipped. That is what let a CI job list a security plugin, fail to
	// install it, and exit 0 with a clean report even under
	// --fail-on-degraded. Skipping is right; staying quiet about it is not.
	out, err := runScanPlugins(context.Background(), t.TempDir(), []string{"nox/definitely-not-installed"})
	if err != nil {
		t.Fatalf("uninstalled required plugin should not abort the scan, got error: %v", err)
	}
	if out == nil {
		t.Fatal("expected a degradation for the uninstalled plugin, got nil output")
	}
	if len(out.Findings) != 0 {
		t.Errorf("expected no findings from an uninstalled plugin, got %d", len(out.Findings))
	}

	var reported bool
	for _, d := range out.Degradations {
		if d.Kind == degrade.Plugin && strings.Contains(d.Detail, "definitely-not-installed") {
			reported = true
		}
	}
	if !reported {
		t.Errorf("the uninstalled required plugin was not reported: %+v", out.Degradations)
	}
}

// The hook must be registered with core at init so `nox scan` runs configured
// analysis plugins without any explicit wiring.
func TestScanPluginHook_Registered(t *testing.T) {
	if core.ScanPluginHook == nil {
		t.Fatal("core.ScanPluginHook was not registered by init()")
	}
}
