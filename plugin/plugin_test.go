package plugin

import (
	"context"
	"net"
	"testing"

	pluginv1 "github.com/felixgeelhaar/hardline/gen/hardline/plugin/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
)

const bufSize = 1024 * 1024

// mockPluginServer implements PluginServiceServer for testing.
type mockPluginServer struct {
	pluginv1.UnimplementedPluginServiceServer
	manifest   *pluginv1.GetManifestResponse
	invokeFunc func(context.Context, *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error)
}

func (m *mockPluginServer) GetManifest(_ context.Context, _ *pluginv1.GetManifestRequest) (*pluginv1.GetManifestResponse, error) {
	return m.manifest, nil
}

func (m *mockPluginServer) InvokeTool(ctx context.Context, req *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
	if m.invokeFunc != nil {
		return m.invokeFunc(ctx, req)
	}
	return &pluginv1.InvokeToolResponse{}, nil
}

// startMockPlugin creates an in-process gRPC server with the given handler
// and returns a client connection.
func startMockPlugin(t *testing.T, srv pluginv1.PluginServiceServer) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(bufSize)

	s := grpc.NewServer()
	pluginv1.RegisterPluginServiceServer(s, srv)

	go func() {
		if err := s.Serve(lis); err != nil {
			// Server stopped.
		}
	}()
	t.Cleanup(func() { s.Stop() })

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("connecting to bufconn: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	return conn
}

func validManifest() *pluginv1.GetManifestResponse {
	return &pluginv1.GetManifestResponse{
		Name:       "test-scanner",
		Version:    "1.0.0",
		ApiVersion: "v1",
		Capabilities: []*pluginv1.Capability{
			{
				Name:        "scanning",
				Description: "Security scanning capability",
				Tools: []*pluginv1.ToolDef{
					{
						Name:        "scan",
						Description: "Run security scan",
						ReadOnly:    true,
					},
					{
						Name:        "analyze",
						Description: "Analyze findings",
						ReadOnly:    true,
					},
				},
				Resources: []*pluginv1.ResourceDef{
					{
						UriTemplate: "hardline://plugins/test-scanner/results",
						Name:        "results",
						Description: "Scan results",
						MimeType:    "application/json",
					},
				},
			},
		},
	}
}

func TestPlugin_Handshake_Success(t *testing.T) {
	conn := startMockPlugin(t, &mockPluginServer{manifest: validManifest()})
	p := NewPlugin(conn)

	if p.State() != StateInit {
		t.Fatalf("initial state = %d, want StateInit", p.State())
	}

	err := p.Handshake(context.Background(), "v1")
	if err != nil {
		t.Fatalf("Handshake() error: %v", err)
	}

	if p.State() != StateReady {
		t.Errorf("state after handshake = %d, want StateReady", p.State())
	}

	info := p.Info()
	if info.Name != "test-scanner" {
		t.Errorf("Name = %q, want %q", info.Name, "test-scanner")
	}
	if info.Version != "1.0.0" {
		t.Errorf("Version = %q, want %q", info.Version, "1.0.0")
	}
	if info.APIVersion != "v1" {
		t.Errorf("APIVersion = %q, want %q", info.APIVersion, "v1")
	}
	if len(info.Capabilities) != 1 {
		t.Fatalf("len(Capabilities) = %d, want 1", len(info.Capabilities))
	}
	cap := info.Capabilities[0]
	if len(cap.Tools) != 2 {
		t.Errorf("len(Tools) = %d, want 2", len(cap.Tools))
	}
	if len(cap.Resources) != 1 {
		t.Errorf("len(Resources) = %d, want 1", len(cap.Resources))
	}
}

func TestPlugin_Handshake_VersionMismatch(t *testing.T) {
	manifest := validManifest()
	manifest.ApiVersion = "v2"
	conn := startMockPlugin(t, &mockPluginServer{manifest: manifest})
	p := NewPlugin(conn)

	err := p.Handshake(context.Background(), "v1")
	if err == nil {
		t.Fatal("expected error for version mismatch")
	}

	if p.State() != StateFailed {
		t.Errorf("state = %d, want StateFailed", p.State())
	}
}

func TestPlugin_InvokeTool_Success(t *testing.T) {
	mock := &mockPluginServer{
		manifest: validManifest(),
		invokeFunc: func(_ context.Context, req *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
			return &pluginv1.InvokeToolResponse{
				Findings: []*pluginv1.Finding{
					{
						Id:       "f-1",
						RuleId:   "SEC-001",
						Severity: pluginv1.Severity_SEVERITY_HIGH,
						Message:  "test finding from " + req.GetToolName(),
					},
				},
				Packages: []*pluginv1.Package{
					{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"},
				},
				AiComponents: []*pluginv1.AIComponent{
					{Name: "agent", Type: "agent", Path: "agents/main.yaml"},
				},
			}, nil
		},
	}
	conn := startMockPlugin(t, mock)
	p := NewPlugin(conn)
	_ = p.Handshake(context.Background(), "v1")

	resp, err := p.InvokeTool(context.Background(), "scan", map[string]any{"target": "/workspace"}, "/workspace")
	if err != nil {
		t.Fatalf("InvokeTool() error: %v", err)
	}
	if len(resp.GetFindings()) != 1 {
		t.Errorf("len(Findings) = %d, want 1", len(resp.GetFindings()))
	}
	if len(resp.GetPackages()) != 1 {
		t.Errorf("len(Packages) = %d, want 1", len(resp.GetPackages()))
	}
	if len(resp.GetAiComponents()) != 1 {
		t.Errorf("len(AiComponents) = %d, want 1", len(resp.GetAiComponents()))
	}
}

func TestPlugin_InvokeTool_BeforeHandshake(t *testing.T) {
	conn := startMockPlugin(t, &mockPluginServer{manifest: validManifest()})
	p := NewPlugin(conn)

	_, err := p.InvokeTool(context.Background(), "scan", nil, "/workspace")
	if err == nil {
		t.Fatal("expected error when invoking before handshake")
	}
}

func TestPlugin_HasTool(t *testing.T) {
	conn := startMockPlugin(t, &mockPluginServer{manifest: validManifest()})
	p := NewPlugin(conn)
	_ = p.Handshake(context.Background(), "v1")

	if !p.HasTool("scan") {
		t.Error("HasTool(scan) = false, want true")
	}
	if !p.HasTool("analyze") {
		t.Error("HasTool(analyze) = false, want true")
	}
	if p.HasTool("nonexistent") {
		t.Error("HasTool(nonexistent) = true, want false")
	}
}

func TestPlugin_Close(t *testing.T) {
	conn := startMockPlugin(t, &mockPluginServer{manifest: validManifest()})
	p := NewPlugin(conn)
	_ = p.Handshake(context.Background(), "v1")

	err := p.Close()
	if err != nil {
		t.Fatalf("Close() error: %v", err)
	}
	if p.State() != StateStopped {
		t.Errorf("state = %d, want StateStopped", p.State())
	}
}

func TestPlugin_Close_Idempotent(t *testing.T) {
	conn := startMockPlugin(t, &mockPluginServer{manifest: validManifest()})
	p := NewPlugin(conn)

	_ = p.Close()
	err := p.Close()
	if err != nil {
		t.Fatalf("second Close() error: %v", err)
	}
	if p.State() != StateStopped {
		t.Errorf("state = %d, want StateStopped", p.State())
	}
}

func TestParseManifest(t *testing.T) {
	resp := validManifest()
	info := parseManifest(resp)

	if info.Name != "test-scanner" {
		t.Errorf("Name = %q, want %q", info.Name, "test-scanner")
	}
	if len(info.Capabilities) != 1 {
		t.Fatalf("len(Capabilities) = %d, want 1", len(info.Capabilities))
	}
	if info.Capabilities[0].Tools[0].Name != "scan" {
		t.Errorf("first tool name = %q, want %q", info.Capabilities[0].Tools[0].Name, "scan")
	}
	if info.Capabilities[0].Resources[0].URITemplate != "hardline://plugins/test-scanner/results" {
		t.Errorf("resource URI template = %q", info.Capabilities[0].Resources[0].URITemplate)
	}
}

func TestBuildInvokeRequest(t *testing.T) {
	req, err := buildInvokeRequest("scan", map[string]any{"target": "/workspace", "verbose": true}, "/workspace")
	if err != nil {
		t.Fatalf("buildInvokeRequest() error: %v", err)
	}
	if req.GetToolName() != "scan" {
		t.Errorf("ToolName = %q, want %q", req.GetToolName(), "scan")
	}
	if req.GetWorkspaceRoot() != "/workspace" {
		t.Errorf("WorkspaceRoot = %q, want %q", req.GetWorkspaceRoot(), "/workspace")
	}

	fields := req.GetInput().GetFields()
	if fields == nil {
		t.Fatal("Input fields should not be nil")
	}
	if v, ok := fields["target"]; !ok || v.GetStringValue() != "/workspace" {
		t.Errorf("input[target] = %v, want /workspace", v)
	}
}

func TestBuildInvokeRequest_NilInput(t *testing.T) {
	req, err := buildInvokeRequest("scan", nil, "/workspace")
	if err != nil {
		t.Fatalf("buildInvokeRequest() error: %v", err)
	}
	if req.GetInput() != nil {
		t.Errorf("Input should be nil for nil input, got %v", req.GetInput())
	}
}

func TestBuildInvokeRequest_InvalidInput(t *testing.T) {
	// structpb.NewStruct does not accept channel types.
	_, err := buildInvokeRequest("scan", map[string]any{"bad": make(chan int)}, "/workspace")
	if err == nil {
		t.Fatal("expected error for invalid input type")
	}
}

func TestPlugin_InvokeTool_WithStructInput(t *testing.T) {
	var capturedInput *structpb.Struct
	mock := &mockPluginServer{
		manifest: validManifest(),
		invokeFunc: func(_ context.Context, req *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
			capturedInput = req.GetInput()
			return &pluginv1.InvokeToolResponse{}, nil
		},
	}
	conn := startMockPlugin(t, mock)
	p := NewPlugin(conn)
	_ = p.Handshake(context.Background(), "v1")

	input := map[string]any{
		"target":  "/workspace",
		"verbose": true,
		"count":   float64(5),
	}
	_, err := p.InvokeTool(context.Background(), "scan", input, "/workspace")
	if err != nil {
		t.Fatalf("InvokeTool() error: %v", err)
	}

	fields := capturedInput.GetFields()
	if fields["target"].GetStringValue() != "/workspace" {
		t.Errorf("target = %v, want /workspace", fields["target"])
	}
	if !fields["verbose"].GetBoolValue() {
		t.Error("verbose should be true")
	}
	if fields["count"].GetNumberValue() != 5 {
		t.Errorf("count = %v, want 5", fields["count"].GetNumberValue())
	}
}
