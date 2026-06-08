package main

import (
	"context"
	"testing"

	"github.com/nox-hq/nox/core"
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
	out, err := runPluginBinaries(context.Background(), t.TempDir(), nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != nil {
		t.Fatalf("expected nil output for no binaries, got %+v", out)
	}
}

func TestRunScanPlugins_UninstalledRequired_Skipped(t *testing.T) {
	// A required plugin that isn't in the install state resolves to zero
	// binaries, so the run is a no-op rather than an error.
	out, err := runScanPlugins(context.Background(), t.TempDir(), []string{"nox/definitely-not-installed"})
	if err != nil {
		t.Fatalf("uninstalled required plugin should be skipped, got error: %v", err)
	}
	if out != nil {
		t.Fatalf("expected nil output, got %+v", out)
	}
}

// The hook must be registered with core at init so `nox scan` runs configured
// analysis plugins without any explicit wiring.
func TestScanPluginHook_Registered(t *testing.T) {
	if core.ScanPluginHook == nil {
		t.Fatal("core.ScanPluginHook was not registered by init()")
	}
}
