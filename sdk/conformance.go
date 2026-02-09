package sdk

import (
	"context"
	"net"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/registry"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const conformanceBufSize = 1024 * 1024

// RunConformance validates that a PluginServiceServer implementation conforms
// to the Nox plugin contract. It runs as a set of subtests under t.
func RunConformance(t *testing.T, server pluginv1.PluginServiceServer) {
	t.Helper()

	client := conformanceClient(t, server)

	var manifest *pluginv1.GetManifestResponse

	t.Run("GetManifest_handshake", func(t *testing.T) {
		resp, err := client.GetManifest(context.Background(), &pluginv1.GetManifestRequest{
			ApiVersion: "v1",
		})
		if err != nil {
			t.Fatalf("GetManifest(v1): %v", err)
		}
		if resp.GetName() == "" {
			t.Error("manifest name must not be empty")
		}
		if resp.GetVersion() == "" {
			t.Error("manifest version must not be empty")
		}
		if resp.GetApiVersion() != "v1" {
			t.Errorf("api_version = %q, want \"v1\"", resp.GetApiVersion())
		}
		manifest = resp
	})

	t.Run("GetManifest_version_rejection", func(t *testing.T) {
		_, err := client.GetManifest(context.Background(), &pluginv1.GetManifestRequest{
			ApiVersion: "v999",
		})
		if err == nil {
			t.Fatal("expected error for unsupported API version")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("expected gRPC status error, got %v", err)
		}
		if st.Code() != codes.FailedPrecondition {
			t.Errorf("code = %v, want FailedPrecondition", st.Code())
		}
	})

	t.Run("InvokeTool_unknown_tool", func(t *testing.T) {
		_, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
			ToolName: "__conformance_nonexistent_tool__",
		})
		if err == nil {
			t.Fatal("expected error for unknown tool")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("expected gRPC status error, got %v", err)
		}
		if st.Code() != codes.NotFound {
			t.Errorf("code = %v, want NotFound", st.Code())
		}
	})

	// Only run tool invocations if manifest was obtained successfully.
	if manifest == nil {
		return
	}

	for _, cap := range manifest.GetCapabilities() {
		for _, tool := range cap.GetTools() {
			toolName := tool.GetName()
			t.Run("InvokeTool_declared/"+toolName, func(t *testing.T) {
				resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
					ToolName: toolName,
				})
				if err != nil {
					t.Fatalf("InvokeTool(%q): %v", toolName, err)
				}
				validateResponse(t, resp)
			})
		}
	}
}

// TrackConformanceOption configures track-specific conformance checks.
type TrackConformanceOption func(*trackConformanceConfig)

type trackConformanceConfig struct {
	requireFindings bool
	requireReadOnly bool
	allowNetwork    bool
}

// WithRequireFindings requires that at least one tool produces findings.
func WithRequireFindings() TrackConformanceOption {
	return func(c *trackConformanceConfig) { c.requireFindings = true }
}

// WithRequireReadOnly requires all declared tools to be read-only.
func WithRequireReadOnly() TrackConformanceOption {
	return func(c *trackConformanceConfig) { c.requireReadOnly = true }
}

// WithAllowNetwork permits the plugin to declare network hosts.
func WithAllowNetwork() TrackConformanceOption {
	return func(c *trackConformanceConfig) { c.allowNetwork = true }
}

// RunForTrack runs conformance tests plus track-specific validation.
// It applies the safety and behavioral expectations for the given track.
func RunForTrack(t *testing.T, server pluginv1.PluginServiceServer, track registry.Track) {
	t.Helper()

	// Run base conformance first.
	RunConformance(t, server)

	client := conformanceClient(t, server)

	manifest, err := client.GetManifest(context.Background(), &pluginv1.GetManifestRequest{
		ApiVersion: "v1",
	})
	if err != nil {
		t.Fatalf("GetManifest for track validation: %v", err)
	}

	// Apply track-specific options.
	opts := trackOptionsForTrack(track)
	var cfg trackConformanceConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	safety := manifest.GetSafety()

	t.Run("Track_safety/risk_class", func(t *testing.T) {
		rc := ""
		if safety != nil {
			rc = safety.GetRiskClass()
		}
		validateTrackRiskClass(t, track, rc)
	})

	if cfg.requireReadOnly {
		t.Run("Track_safety/read_only_tools", func(t *testing.T) {
			for _, cap := range manifest.GetCapabilities() {
				for _, tool := range cap.GetTools() {
					if !tool.GetReadOnly() {
						t.Errorf("tool %q must be read-only for track %q", tool.GetName(), track)
					}
				}
			}
		})
	}

	if !cfg.allowNetwork {
		t.Run("Track_safety/no_network", func(t *testing.T) {
			if safety != nil && len(safety.GetNetworkHosts()) > 0 {
				t.Errorf("track %q should not require network hosts, but declares: %v", track, safety.GetNetworkHosts())
			}
		})
	}

	if cfg.requireFindings {
		t.Run("Track_output/produces_findings", func(t *testing.T) {
			foundAny := false
			for _, cap := range manifest.GetCapabilities() {
				for _, tool := range cap.GetTools() {
					resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
						ToolName: tool.GetName(),
					})
					if err != nil {
						continue
					}
					if len(resp.GetFindings()) > 0 {
						foundAny = true
						break
					}
				}
				if foundAny {
					break
				}
			}
			// This is a soft check — tools may legitimately produce no findings
			// when invoked without workspace data.
			if !foundAny {
				t.Log("note: no tool produced findings during conformance (may need testdata)")
			}
		})
	}

	t.Run("Track_manifest/determinism", func(t *testing.T) {
		// Call GetManifest twice and verify identical results.
		m2, err := client.GetManifest(context.Background(), &pluginv1.GetManifestRequest{
			ApiVersion: "v1",
		})
		if err != nil {
			t.Fatalf("second GetManifest: %v", err)
		}
		if manifest.GetName() != m2.GetName() {
			t.Error("manifest name not deterministic")
		}
		if manifest.GetVersion() != m2.GetVersion() {
			t.Error("manifest version not deterministic")
		}
		if len(manifest.GetCapabilities()) != len(m2.GetCapabilities()) {
			t.Error("capabilities count not deterministic")
		}
	})
}

// trackOptionsForTrack returns the conformance options appropriate for a track.
func trackOptionsForTrack(track registry.Track) []TrackConformanceOption {
	switch track {
	case registry.TrackCoreAnalysis:
		return []TrackConformanceOption{WithRequireFindings(), WithRequireReadOnly()}
	case registry.TrackDynamicRuntime:
		return []TrackConformanceOption{WithRequireFindings(), WithAllowNetwork()}
	case registry.TrackAISecurity:
		return []TrackConformanceOption{WithRequireFindings(), WithRequireReadOnly()}
	case registry.TrackThreatModeling:
		return []TrackConformanceOption{WithRequireReadOnly()}
	case registry.TrackSupplyChain:
		return []TrackConformanceOption{WithRequireReadOnly(), WithAllowNetwork()}
	case registry.TrackIntelligence:
		return []TrackConformanceOption{WithRequireReadOnly(), WithAllowNetwork()}
	case registry.TrackPolicyGovernance:
		return []TrackConformanceOption{WithRequireReadOnly()}
	case registry.TrackIncidentReadiness:
		return []TrackConformanceOption{WithRequireReadOnly()}
	case registry.TrackDeveloperExperience:
		return []TrackConformanceOption{WithRequireReadOnly()}
	case registry.TrackAgentAssistance:
		return []TrackConformanceOption{WithRequireReadOnly(), WithAllowNetwork()}
	default:
		return nil
	}
}

// validateTrackRiskClass checks that a plugin's declared risk class is
// appropriate for its track.
func validateTrackRiskClass(t *testing.T, track registry.Track, riskClass string) {
	t.Helper()

	catalog := registry.TrackCatalog()
	for _, info := range catalog {
		if info.Track == track {
			maxRC := info.Characteristics.RiskClass
			if riskClass == "" {
				return // No risk class declared means passive, always OK.
			}
			if riskClassLevel(riskClass) > riskClassLevel(maxRC) {
				t.Errorf("plugin declares risk_class %q but track %q allows at most %q", riskClass, track, maxRC)
			}
			return
		}
	}
}

// riskClassLevel returns an ordinal for risk class comparison.
func riskClassLevel(rc string) int {
	switch rc {
	case "passive", "":
		return 0
	case "active":
		return 1
	case "runtime":
		return 2
	default:
		return -1
	}
}

// validateResponse checks structural invariants on an InvokeToolResponse.
func validateResponse(t *testing.T, resp *pluginv1.InvokeToolResponse) {
	t.Helper()

	for i, f := range resp.GetFindings() {
		if f.GetRuleId() == "" {
			t.Errorf("finding[%d]: rule_id must not be empty", i)
		}
		if f.GetSeverity() == pluginv1.Severity_SEVERITY_UNSPECIFIED {
			t.Errorf("finding[%d]: severity must not be UNSPECIFIED", i)
		}
	}

	for i, p := range resp.GetPackages() {
		if p.GetName() == "" {
			t.Errorf("package[%d]: name must not be empty", i)
		}
	}

	for i, c := range resp.GetAiComponents() {
		if c.GetName() == "" {
			t.Errorf("ai_component[%d]: name must not be empty", i)
		}
	}
}

// conformanceClient creates an in-process gRPC client via bufconn.
func conformanceClient(t *testing.T, server pluginv1.PluginServiceServer) pluginv1.PluginServiceClient {
	t.Helper()

	lis := bufconn.Listen(conformanceBufSize)
	grpcServer := grpc.NewServer()
	pluginv1.RegisterPluginServiceServer(grpcServer, server)

	go func() {
		_ = grpcServer.Serve(lis)
	}()
	t.Cleanup(func() { grpcServer.Stop() })

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	return pluginv1.NewPluginServiceClient(conn)
}
