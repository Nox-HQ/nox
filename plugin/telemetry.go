package plugin

import (
	"sync"
	"time"
)

// PluginTelemetry holds metrics collected during a plugin's lifetime.
type PluginTelemetry struct {
	PluginName        string        `json:"plugin_name"`
	TotalDuration     time.Duration `json:"total_duration_ns"`
	InvocationCount   int           `json:"invocation_count"`
	FindingsCount     int           `json:"findings_count"`
	PackagesCount     int           `json:"packages_count"`
	AIComponentsCount int           `json:"ai_components_count"`
	DiagnosticsCount  int           `json:"diagnostics_count"`
	ErrorCount        int           `json:"error_count"`
	PeakMemoryBytes   int64         `json:"peak_memory_bytes,omitempty"`
}

// telemetryCollector accumulates per-plugin metrics in a thread-safe manner.
type telemetryCollector struct {
	entries map[string]*PluginTelemetry
	mu      sync.Mutex
}

func newTelemetryCollector() *telemetryCollector {
	return &telemetryCollector{
		entries: make(map[string]*PluginTelemetry),
	}
}

// Record adds an invocation's metrics to the collector.
func (tc *telemetryCollector) Record(pluginName string, duration time.Duration, findings, packages, aiComponents, diagnostics int, errored bool) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	entry, ok := tc.entries[pluginName]
	if !ok {
		entry = &PluginTelemetry{PluginName: pluginName}
		tc.entries[pluginName] = entry
	}

	entry.TotalDuration += duration
	entry.InvocationCount++
	entry.FindingsCount += findings
	entry.PackagesCount += packages
	entry.AIComponentsCount += aiComponents
	entry.DiagnosticsCount += diagnostics
	if errored {
		entry.ErrorCount++
	}
}

// Snapshot returns a copy of all collected telemetry.
func (tc *telemetryCollector) Snapshot() []PluginTelemetry {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	out := make([]PluginTelemetry, 0, len(tc.entries))
	for _, entry := range tc.entries {
		cp := *entry
		out = append(out, cp)
	}
	return out
}
