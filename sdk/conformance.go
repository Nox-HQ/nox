package sdk

import (
	"context"
	"net"
	"testing"

	pluginv1 "github.com/felixgeelhaar/hardline/gen/hardline/plugin/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const conformanceBufSize = 1024 * 1024

// RunConformance validates that a PluginServiceServer implementation conforms
// to the Hardline plugin contract. It runs as a set of subtests under t.
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
