package plugin

import (
	"context"
	"strings"
	"testing"
	"time"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
)

func TestRuntimeViolation_Error(t *testing.T) {
	v := RuntimeViolation{
		Type:       ViolationRateLimit,
		PluginName: "test-plugin",
		Message:    "exceeded 60 RPM",
		Timestamp:  time.Now(),
	}

	got := v.Error()
	if !strings.Contains(got, "rate_limit_exceeded") {
		t.Errorf("Error() should contain violation type, got %q", got)
	}
	if !strings.Contains(got, "test-plugin") {
		t.Errorf("Error() should contain plugin name, got %q", got)
	}
	if !strings.Contains(got, "exceeded 60 RPM") {
		t.Errorf("Error() should contain message, got %q", got)
	}
}

func TestHandleViolation_LogsAndTerminates(t *testing.T) {
	mock := &mockPluginServer{
		manifest: validManifest(),
		invokeFunc: func(_ context.Context, _ *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
			return &pluginv1.InvokeToolResponse{}, nil
		},
	}
	conn := startMockPlugin(t, mock)
	h := newTestHost()
	if err := h.RegisterPlugin(context.Background(), conn); err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}

	p := h.plugins["test-scanner"]
	v := RuntimeViolation{
		Type:       ViolationRateLimit,
		PluginName: "test-scanner",
		Message:    "exceeded limit",
		Timestamp:  time.Now(),
	}

	h.handleViolation(v, p)

	// Plugin should be removed from host maps.
	if len(h.plugins) != 0 {
		t.Errorf("plugin should be removed, got %d plugins", len(h.plugins))
	}
	if len(h.toolIndex) != 0 {
		t.Errorf("tool index should be empty, got %d entries", len(h.toolIndex))
	}

	// Diagnostic should be recorded.
	diags := h.Diagnostics()
	found := false
	for _, d := range diags {
		if strings.Contains(d.Message, "exceeded limit") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected diagnostic for violation")
	}

	// Violation should be recorded.
	violations := h.Violations()
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].Type != ViolationRateLimit {
		t.Errorf("violation type = %q, want %q", violations[0].Type, ViolationRateLimit)
	}

	// Plugin state should be failed.
	if p.State() != StateFailed {
		t.Errorf("plugin state = %d, want StateFailed", p.State())
	}
}

func TestHandleViolation_AlreadyStopped(t *testing.T) {
	mock := &mockPluginServer{
		manifest: validManifest(),
	}
	conn := startMockPlugin(t, mock)
	h := newTestHost()
	if err := h.RegisterPlugin(context.Background(), conn); err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}

	p := h.plugins["test-scanner"]
	// Stop plugin first.
	_ = p.Close()

	v := RuntimeViolation{
		Type:       ViolationBandwidth,
		PluginName: "test-scanner",
		Message:    "bandwidth exceeded",
		Timestamp:  time.Now(),
	}

	// Should not panic on already-stopped plugin.
	h.handleViolation(v, p)

	violations := h.Violations()
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation even for stopped plugin, got %d", len(violations))
	}
}
