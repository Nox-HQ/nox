package plugin

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/analyzers/deps"
	"github.com/nox-hq/nox/core/findings"
	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
)

// egressPlugin is a plugin with two tools of one kind (post-scan or scan):
// "judge", whose safety is given, and "local", which declares nothing. The
// sibling shows the refusal does not take the plugin down.
func egressPlugin(t *testing.T, postScan bool, toolSafety, pluginSafety *pluginv1.SafetyRequirements) (mock *mockPluginServer, calls func() []string) {
	t.Helper()
	var mu sync.Mutex
	var got []string
	mock = &mockPluginServer{
		manifest: &pluginv1.GetManifestResponse{
			Name:       "llm-judge",
			Version:    "1.0.0",
			ApiVersion: HostAPIVersion,
			Safety:     pluginSafety,
			Capabilities: []*pluginv1.Capability{{
				Name: "triage",
				Tools: []*pluginv1.ToolDef{
					{Name: "judge", ReadOnly: true, RequiresScanContext: postScan, Safety: toolSafety},
					{Name: "local", ReadOnly: true, RequiresScanContext: postScan, Safety: &pluginv1.SafetyRequirements{RiskClass: "passive"}},
				},
			}},
		},
		invokeFunc: func(_ context.Context, req *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
			mu.Lock()
			got = append(got, req.GetToolName())
			mu.Unlock()
			return &pluginv1.InvokeToolResponse{}, nil
		},
	}
	calls = func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), got...) }
	return mock, calls
}

func egressPolicy() *Policy {
	p := DefaultPolicy()
	p.AllowedNetworkHosts = []string{"api.anthropic.com", "localhost"}
	return &p
}

func emptyResult() *core.ScanResult {
	return &core.ScanResult{Findings: findings.NewFindingSet(), Inventory: &deps.PackageInventory{}, AIInventory: ai.NewInventory()}
}

func TestHost_OfflineRefusesNetworkTools(t *testing.T) {
	anthropic := &pluginv1.SafetyRequirements{NetworkHosts: []string{"api.anthropic.com"}, RiskClass: "passive"}
	loopback := &pluginv1.SafetyRequirements{NetworkHosts: []string{"localhost"}, RiskClass: "passive"}

	cases := []struct {
		name         string
		postScan     bool
		offline      bool
		toolSafety   *pluginv1.SafetyRequirements
		pluginSafety *pluginv1.SafetyRequirements
		wantJudge    bool
		wantEgress   bool
	}{
		{"post-scan offline, tool declares a host", true, true, anthropic, nil, false, false},
		{"post-scan online, tool declares a host", true, false, anthropic, nil, true, true},
		{"post-scan offline, plugin-level host inherited", true, true, nil, anthropic, false, false},
		{"post-scan offline, loopback only", true, true, loopback, nil, true, false},
		{"scan offline, tool declares a host", false, true, anthropic, nil, false, false},
		{"scan online, tool declares a host", false, false, anthropic, nil, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mock, calls := egressPlugin(t, tc.postScan, tc.toolSafety, tc.pluginSafety)
			conn := startMockPlugin(t, mock)
			h := newTestHost(WithPolicy(egressPolicy()), WithOffline(tc.offline))
			if err := h.RegisterPlugin(context.Background(), conn); err != nil {
				t.Fatalf("RegisterPlugin: %v", err)
			}

			if tc.postScan {
				if err := h.InvokePostScan(context.Background(), emptyResult(), t.TempDir()); err != nil {
					t.Fatalf("InvokePostScan: %v", err)
				}
			} else {
				for _, tool := range []string{"judge", "local"} {
					if _, err := h.InvokeAll(context.Background(), tool, nil, t.TempDir()); err != nil {
						t.Fatalf("InvokeAll(%s): %v", tool, err)
					}
				}
			}

			got := strings.Join(calls(), ",")
			if judged := strings.Contains(got, "judge"); judged != tc.wantJudge {
				t.Errorf("judge invoked = %v, want %v (calls %q)", judged, tc.wantJudge, got)
			}
			if !strings.Contains(got, "local") {
				t.Errorf("the sibling tool with no network declaration did not run (calls %q): the refusal took the plugin down", got)
			}

			refused := 0
			for _, d := range h.Diagnostics() {
				if strings.Contains(d.Message, "offline scan") && strings.Contains(d.Message, `"judge"`) {
					refused++
					if d.Severity != "error" {
						t.Errorf("offline refusal severity %q, want error (it must become a degradation)", d.Severity)
					}
				}
			}
			if wantRefused := !tc.wantJudge; (refused == 1) != wantRefused {
				t.Errorf("offline refusal diagnostics = %d, want refused=%v", refused, wantRefused)
			}
			if len(h.Violations()) != 0 {
				t.Errorf("an offline refusal recorded a violation: %v", h.Violations())
			}

			eg := h.Egress()
			if (len(eg) == 1) != tc.wantEgress {
				t.Fatalf("Egress = %+v, want one entry: %v", eg, tc.wantEgress)
			}
			if tc.wantEgress && (eg[0].Tool != "judge" || strings.Join(eg[0].Hosts, ",") != "api.anthropic.com") {
				t.Errorf("Egress = %+v", eg[0])
			}
		})
	}
}

func TestHost_EgressRecordedOncePerTool(t *testing.T) {
	mock, _ := egressPlugin(t, false, &pluginv1.SafetyRequirements{NetworkHosts: []string{"api.anthropic.com"}, RiskClass: "passive"}, nil)
	h := newTestHost(WithPolicy(egressPolicy()))
	if err := h.RegisterPlugin(context.Background(), startMockPlugin(t, mock)); err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}
	for range 3 {
		if _, err := h.InvokeAll(context.Background(), "judge", nil, t.TempDir()); err != nil {
			t.Fatal(err)
		}
	}
	if eg := h.Egress(); len(eg) != 1 {
		t.Errorf("Egress has %d entries after three calls of one tool, want 1: %+v", len(eg), eg)
	}
}
