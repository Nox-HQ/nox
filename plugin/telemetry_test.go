package plugin

import (
	"testing"
	"time"
)

func TestTelemetryCollectorRecord(t *testing.T) {
	tc := newTelemetryCollector()

	tc.Record("nox/sast", 100*time.Millisecond, 5, 2, 0, 1, false)
	tc.Record("nox/sast", 200*time.Millisecond, 3, 1, 0, 0, false)
	tc.Record("nox/dast", 500*time.Millisecond, 0, 0, 0, 0, true)

	snap := tc.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("snapshot entries = %d, want 2", len(snap))
	}

	// Find sast entry.
	var sast, dast *PluginTelemetry
	for i := range snap {
		switch snap[i].PluginName {
		case "nox/sast":
			sast = &snap[i]
		case "nox/dast":
			dast = &snap[i]
		}
	}

	if sast == nil {
		t.Fatal("missing nox/sast telemetry")
	}
	if sast.InvocationCount != 2 {
		t.Errorf("sast invocations = %d, want 2", sast.InvocationCount)
	}
	if sast.FindingsCount != 8 {
		t.Errorf("sast findings = %d, want 8", sast.FindingsCount)
	}
	if sast.PackagesCount != 3 {
		t.Errorf("sast packages = %d, want 3", sast.PackagesCount)
	}
	if sast.DiagnosticsCount != 1 {
		t.Errorf("sast diagnostics = %d, want 1", sast.DiagnosticsCount)
	}
	if sast.ErrorCount != 0 {
		t.Errorf("sast errors = %d, want 0", sast.ErrorCount)
	}
	if sast.TotalDuration != 300*time.Millisecond {
		t.Errorf("sast duration = %v, want 300ms", sast.TotalDuration)
	}

	if dast == nil {
		t.Fatal("missing nox/dast telemetry")
	}
	if dast.ErrorCount != 1 {
		t.Errorf("dast errors = %d, want 1", dast.ErrorCount)
	}
}

func TestTelemetrySnapshotReturnsCopy(t *testing.T) {
	tc := newTelemetryCollector()
	tc.Record("test", 10*time.Millisecond, 1, 0, 0, 0, false)

	snap1 := tc.Snapshot()
	snap1[0].FindingsCount = 999

	snap2 := tc.Snapshot()
	if snap2[0].FindingsCount != 1 {
		t.Error("Snapshot should return copies, not references")
	}
}

func TestTelemetryEmptySnapshot(t *testing.T) {
	tc := newTelemetryCollector()
	snap := tc.Snapshot()
	if len(snap) != 0 {
		t.Errorf("empty snapshot has %d entries", len(snap))
	}
}
