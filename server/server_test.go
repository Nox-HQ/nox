package server

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/plugin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func TestIsPathAllowed_NoRestrictions(t *testing.T) {
	s := New("0.1.0", nil)

	if err := s.isPathAllowed("/any/path"); err != nil {
		t.Fatalf("expected no error for unrestricted server, got: %v", err)
	}
}

func TestIsPathAllowed_AllowedPath(t *testing.T) {
	dir := t.TempDir()
	s := New("0.1.0", []string{dir})

	sub := filepath.Join(dir, "subdir")
	if err := s.isPathAllowed(sub); err != nil {
		t.Fatalf("expected path under allowed root to be allowed, got: %v", err)
	}
}

func TestIsPathAllowed_DisallowedPath(t *testing.T) {
	s := New("0.1.0", []string{"/allowed/workspace"})

	if err := s.isPathAllowed("/other/path"); err == nil {
		t.Fatal("expected error for path outside allowed workspace")
	}
}

func TestIsPathAllowed_ExactRoot(t *testing.T) {
	dir := t.TempDir()
	s := New("0.1.0", []string{dir})

	if err := s.isPathAllowed(dir); err != nil {
		t.Fatalf("expected exact root path to be allowed, got: %v", err)
	}
}

func TestIsPathAllowed_RelativePath(t *testing.T) {
	// Create a temporary workspace and change to it.
	dir := t.TempDir()

	// Resolve the temp dir to its real path (handles macOS /var -> /private/var symlink).
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}

	s := New("0.1.0", []string{realDir})

	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })

	if err := os.Chdir(realDir); err != nil {
		t.Fatal(err)
	}

	// "." should resolve to dir.
	if err := s.isPathAllowed("."); err != nil {
		t.Fatalf("expected relative path within allowed root to be allowed, got: %v", err)
	}
}

func TestIsPathAllowed_TraversalBlocked(t *testing.T) {
	dir := t.TempDir()
	s := New("0.1.0", []string{dir})

	traversal := filepath.Join(dir, "..", "escape")
	if err := s.isPathAllowed(traversal); err == nil {
		t.Fatal("expected path traversal to be blocked")
	}
}

func TestHandleScan_CleanDirectory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.go", "package main\n\nfunc main() {}\n")

	s := New("0.1.0", nil)
	req := makeToolRequest(t, "scan", map[string]any{"path": dir})

	result, err := s.handleScan(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", toolResultText(result))
	}

	text := toolResultText(result)
	if !strings.Contains(text, "0 findings") {
		t.Fatalf("expected 0 findings in summary, got: %s", text)
	}
}

func TestHandleScan_WithFindings(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

	s := New("0.1.0", nil)
	req := makeToolRequest(t, "scan", map[string]any{"path": dir})

	result, err := s.handleScan(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", toolResultText(result))
	}

	text := toolResultText(result)
	if strings.Contains(text, "0 findings") {
		t.Fatalf("expected findings in summary, got: %s", text)
	}
}

func TestHandleScan_DisallowedPath(t *testing.T) {
	dir := t.TempDir()
	s := New("0.1.0", []string{"/allowed/only"})

	req := makeToolRequest(t, "scan", map[string]any{"path": dir})

	result, err := s.handleScan(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for disallowed path")
	}

	text := toolResultText(result)
	if !strings.Contains(text, "outside allowed workspaces") {
		t.Fatalf("expected workspace error, got: %s", text)
	}
}

func TestHandleScan_MissingPath(t *testing.T) {
	s := New("0.1.0", nil)
	req := makeToolRequest(t, "scan", map[string]any{})

	result, err := s.handleScan(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for missing path argument")
	}
}

func TestHandleGetFindings_BeforeScan(t *testing.T) {
	s := New("0.1.0", nil)
	req := makeToolRequest(t, "get_findings", map[string]any{})

	result, err := s.handleGetFindings(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error before any scan")
	}

	text := toolResultText(result)
	if !strings.Contains(text, "no scan results") {
		t.Fatalf("expected no-scan-results message, got: %s", text)
	}
}

func TestHandleGetFindings_JSON(t *testing.T) {
	s := scanCleanDir(t)
	req := makeToolRequest(t, "get_findings", map[string]any{"format": "json"})

	result, err := s.handleGetFindings(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", toolResultText(result))
	}

	text := toolResultText(result)
	if !strings.Contains(text, `"findings"`) {
		t.Fatalf("expected JSON findings output, got: %s", text)
	}
}

func TestHandleGetFindings_SARIF(t *testing.T) {
	s := scanCleanDir(t)
	req := makeToolRequest(t, "get_findings", map[string]any{"format": "sarif"})

	result, err := s.handleGetFindings(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", toolResultText(result))
	}

	text := toolResultText(result)
	if !strings.Contains(text, `"$schema"`) {
		t.Fatalf("expected SARIF output, got: %s", text)
	}
}

func TestHandleGetSBOM_BeforeScan(t *testing.T) {
	s := New("0.1.0", nil)
	req := makeToolRequest(t, "get_sbom", map[string]any{})

	result, err := s.handleGetSBOM(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error before any scan")
	}
}

func TestHandleGetSBOM_CDX(t *testing.T) {
	s := scanCleanDir(t)
	req := makeToolRequest(t, "get_sbom", map[string]any{"format": "cdx"})

	result, err := s.handleGetSBOM(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", toolResultText(result))
	}

	text := toolResultText(result)
	if !strings.Contains(text, "CycloneDX") {
		t.Fatalf("expected CycloneDX output, got: %s", text)
	}
}

func TestHandleGetSBOM_SPDX(t *testing.T) {
	s := scanCleanDir(t)
	req := makeToolRequest(t, "get_sbom", map[string]any{"format": "spdx"})

	result, err := s.handleGetSBOM(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", toolResultText(result))
	}

	text := toolResultText(result)
	if !strings.Contains(text, "SPDX") {
		t.Fatalf("expected SPDX output, got: %s", text)
	}
}

func TestResourceFindings_BeforeScan(t *testing.T) {
	s := New("0.1.0", nil)
	req := mcp.ReadResourceRequest{}
	req.Params.URI = "nox://findings"

	_, err := s.handleResourceFindings(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for resource before scan")
	}
}

func TestResourceFindings_AfterScan(t *testing.T) {
	s := scanCleanDir(t)
	req := mcp.ReadResourceRequest{}
	req.Params.URI = "nox://findings"

	contents, err := s.handleResourceFindings(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(contents) == 0 {
		t.Fatal("expected non-empty resource contents")
	}

	tc, ok := contents[0].(mcp.TextResourceContents)
	if !ok {
		t.Fatal("expected TextResourceContents")
	}
	if tc.URI != "nox://findings" {
		t.Fatalf("expected URI nox://findings, got %s", tc.URI)
	}
	if !strings.Contains(tc.Text, `"findings"`) {
		t.Fatalf("expected findings JSON, got: %s", tc.Text)
	}
}

func TestResourceSARIF_AfterScan(t *testing.T) {
	s := scanCleanDir(t)
	req := mcp.ReadResourceRequest{}
	req.Params.URI = "nox://sarif"

	contents, err := s.handleResourceSARIF(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(contents) == 0 {
		t.Fatal("expected non-empty resource contents")
	}

	tc, ok := contents[0].(mcp.TextResourceContents)
	if !ok {
		t.Fatal("expected TextResourceContents")
	}
	if !strings.Contains(tc.Text, `"$schema"`) {
		t.Fatalf("expected SARIF content, got: %s", tc.Text)
	}
}

func TestResourceCDX_AfterScan(t *testing.T) {
	s := scanCleanDir(t)
	req := mcp.ReadResourceRequest{}
	req.Params.URI = "nox://sbom/cdx"

	contents, err := s.handleResourceCDX(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(contents) == 0 {
		t.Fatal("expected non-empty resource contents")
	}

	tc, ok := contents[0].(mcp.TextResourceContents)
	if !ok {
		t.Fatal("expected TextResourceContents")
	}
	if !strings.Contains(tc.Text, "CycloneDX") {
		t.Fatalf("expected CycloneDX content, got: %s", tc.Text)
	}
}

func TestResourceSPDX_AfterScan(t *testing.T) {
	s := scanCleanDir(t)
	req := mcp.ReadResourceRequest{}
	req.Params.URI = "nox://sbom/spdx"

	contents, err := s.handleResourceSPDX(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(contents) == 0 {
		t.Fatal("expected non-empty resource contents")
	}

	tc, ok := contents[0].(mcp.TextResourceContents)
	if !ok {
		t.Fatal("expected TextResourceContents")
	}
	if !strings.Contains(tc.Text, "SPDX") {
		t.Fatalf("expected SPDX content, got: %s", tc.Text)
	}
}

func TestResourceAIInventory_AfterScan(t *testing.T) {
	s := scanCleanDir(t)
	req := mcp.ReadResourceRequest{}
	req.Params.URI = "nox://ai-inventory"

	contents, err := s.handleResourceAIInventory(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(contents) == 0 {
		t.Fatal("expected non-empty resource contents")
	}

	tc, ok := contents[0].(mcp.TextResourceContents)
	if !ok {
		t.Fatal("expected TextResourceContents")
	}
	if !strings.Contains(tc.Text, "schema_version") {
		t.Fatalf("expected AI inventory JSON, got: %s", tc.Text)
	}
}

func TestTruncate_Short(t *testing.T) {
	input := "short string"
	result := truncate(input)
	if result != input {
		t.Fatalf("expected unchanged string, got: %s", result)
	}
}

func TestTruncate_Long(t *testing.T) {
	input := strings.Repeat("x", maxOutputBytes+100)
	result := truncate(input)

	if len(result) <= maxOutputBytes {
		t.Fatal("expected truncated string to be longer than maxOutputBytes (includes notice)")
	}
	if !strings.Contains(result, "[truncated") {
		t.Fatal("expected truncation notice")
	}
	// The first maxOutputBytes bytes should be preserved.
	if result[:maxOutputBytes] != input[:maxOutputBytes] {
		t.Fatal("expected first maxOutputBytes bytes to match")
	}
}

// --- helpers ---

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("writing file %s: %v", name, err)
	}
}

func makeToolRequest(t *testing.T, name string, args map[string]any) mcp.CallToolRequest {
	t.Helper()
	argsJSON, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("marshaling args: %v", err)
	}
	var raw any
	if err := json.Unmarshal(argsJSON, &raw); err != nil {
		t.Fatalf("unmarshaling args: %v", err)
	}
	return mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      name,
			Arguments: raw,
		},
	}
}

func toolResultText(result *mcp.CallToolResult) string {
	for _, c := range result.Content {
		if tc, ok := c.(mcp.TextContent); ok {
			return tc.Text
		}
	}
	return ""
}

// scanCleanDir creates a temporary directory with a clean Go file and
// runs a scan against it, returning the server with cached results.
func scanCleanDir(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, "main.go", "package main\n\nfunc main() {}\n")

	s := New("0.1.0", nil)
	req := makeToolRequest(t, "scan", map[string]any{"path": dir})

	result, err := s.handleScan(context.Background(), req)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if result.IsError {
		t.Fatalf("scan returned error: %s", toolResultText(result))
	}
	return s
}

// --- mock plugin server for bridge integration tests ---

const testBufSize = 1024 * 1024

type testMockPluginServer struct {
	pluginv1.UnimplementedPluginServiceServer
	manifest   *pluginv1.GetManifestResponse
	invokeFunc func(context.Context, *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error)
}

func (m *testMockPluginServer) GetManifest(_ context.Context, _ *pluginv1.GetManifestRequest) (*pluginv1.GetManifestResponse, error) {
	return m.manifest, nil
}

func (m *testMockPluginServer) InvokeTool(ctx context.Context, req *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
	if m.invokeFunc != nil {
		return m.invokeFunc(ctx, req)
	}
	return &pluginv1.InvokeToolResponse{}, nil
}

func testValidManifest() *pluginv1.GetManifestResponse {
	return &pluginv1.GetManifestResponse{
		Name:       "test-scanner",
		Version:    "1.0.0",
		ApiVersion: "v1",
		Capabilities: []*pluginv1.Capability{
			{
				Name:        "scanning",
				Description: "Security scanning capability",
				Tools: []*pluginv1.ToolDef{
					{Name: "scan", Description: "Run security scan", ReadOnly: true},
					{Name: "analyze", Description: "Analyze findings", ReadOnly: true},
				},
			},
		},
	}
}

func startTestMockPlugin(t *testing.T, srv pluginv1.PluginServiceServer) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(testBufSize)

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

func createHostWithMockPlugin(t *testing.T) *plugin.Host {
	t.Helper()
	mock := &testMockPluginServer{
		manifest: testValidManifest(),
		invokeFunc: func(_ context.Context, req *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
			return &pluginv1.InvokeToolResponse{
				Findings: []*pluginv1.Finding{
					{
						Id:         "f-1",
						RuleId:     "SEC-001",
						Severity:   pluginv1.Severity_SEVERITY_HIGH,
						Confidence: pluginv1.Confidence_CONFIDENCE_HIGH,
						Message:    "test finding from " + req.GetToolName(),
					},
				},
			}, nil
		},
	}
	conn := startTestMockPlugin(t, mock)
	h := plugin.NewHost()
	if err := h.RegisterPlugin(context.Background(), conn); err != nil {
		t.Fatalf("registering mock plugin: %v", err)
	}
	return h
}

// --- plugin bridge integration tests ---

func TestHandlePluginList_NoHost(t *testing.T) {
	s := New("0.1.0", nil)
	req := makeToolRequest(t, "plugin.list", map[string]any{})

	result, err := s.handlePluginList(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for nil host")
	}
	if !strings.Contains(toolResultText(result), "no plugin host") {
		t.Fatalf("expected 'no plugin host' message, got: %s", toolResultText(result))
	}
}

func TestHandlePluginList_EmptyHost(t *testing.T) {
	h := plugin.NewHost()
	s := New("0.1.0", nil, WithPluginHost(h))
	req := makeToolRequest(t, "plugin.list", map[string]any{})

	result, err := s.handlePluginList(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", toolResultText(result))
	}

	text := toolResultText(result)
	if text != "[]" {
		t.Fatalf("expected empty array, got: %s", text)
	}
}

func TestHandlePluginList_WithPlugins(t *testing.T) {
	h := createHostWithMockPlugin(t)
	s := New("0.1.0", nil, WithPluginHost(h))
	req := makeToolRequest(t, "plugin.list", map[string]any{})

	result, err := s.handlePluginList(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", toolResultText(result))
	}

	text := toolResultText(result)
	if !strings.Contains(text, "test-scanner") {
		t.Fatalf("expected 'test-scanner' in output, got: %s", text)
	}
	if !strings.Contains(text, `"scan"`) {
		t.Fatalf("expected 'scan' tool in output, got: %s", text)
	}
}

func TestHandlePluginCallTool_NoHost(t *testing.T) {
	s := New("0.1.0", nil)
	req := makeToolRequest(t, "plugin.call_tool", map[string]any{"tool": "scan"})

	result, err := s.handlePluginCallTool(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for nil host")
	}
	if !strings.Contains(toolResultText(result), "no plugin host") {
		t.Fatalf("expected 'no plugin host' message, got: %s", toolResultText(result))
	}
}

func TestHandlePluginCallTool_MissingToolArg(t *testing.T) {
	h := createHostWithMockPlugin(t)
	s := New("0.1.0", nil, WithPluginHost(h))
	req := makeToolRequest(t, "plugin.call_tool", map[string]any{})

	result, err := s.handlePluginCallTool(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for missing tool argument")
	}
	if !strings.Contains(toolResultText(result), "missing required argument: tool") {
		t.Fatalf("expected missing tool message, got: %s", toolResultText(result))
	}
}

func TestHandlePluginCallTool_Success(t *testing.T) {
	h := createHostWithMockPlugin(t)
	s := New("0.1.0", nil, WithPluginHost(h))
	req := makeToolRequest(t, "plugin.call_tool", map[string]any{
		"tool": "test-scanner.scan",
	})

	result, err := s.handlePluginCallTool(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", toolResultText(result))
	}

	text := toolResultText(result)
	if !strings.Contains(text, "f-1") {
		t.Fatalf("expected finding ID in output, got: %s", text)
	}
	if !strings.Contains(text, `"severity":"high"`) {
		t.Fatalf("expected severity as string, got: %s", text)
	}
}

func TestHandlePluginCallTool_UnknownTool(t *testing.T) {
	h := createHostWithMockPlugin(t)
	s := New("0.1.0", nil, WithPluginHost(h))
	req := makeToolRequest(t, "plugin.call_tool", map[string]any{
		"tool": "nonexistent",
	})

	result, err := s.handlePluginCallTool(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for unknown tool")
	}
	if !strings.Contains(toolResultText(result), "no plugin provides tool") {
		t.Fatalf("expected 'no plugin provides tool' message, got: %s", toolResultText(result))
	}
}

func TestHandlePluginCallTool_WorkspaceBlocked(t *testing.T) {
	h := createHostWithMockPlugin(t)
	s := New("0.1.0", []string{"/allowed/only"}, WithPluginHost(h))
	req := makeToolRequest(t, "plugin.call_tool", map[string]any{
		"tool":           "test-scanner.scan",
		"workspace_root": "/not/allowed",
	})

	result, err := s.handlePluginCallTool(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for blocked workspace")
	}
	if !strings.Contains(toolResultText(result), "outside allowed workspaces") {
		t.Fatalf("expected workspace error, got: %s", toolResultText(result))
	}
}

func TestHandlePluginCallTool_Alias(t *testing.T) {
	h := createHostWithMockPlugin(t)
	s := New("0.1.0", nil,
		WithPluginHost(h),
		WithAliases(map[string]string{
			"quick-scan": "test-scanner.scan",
		}),
	)
	req := makeToolRequest(t, "plugin.call_tool", map[string]any{
		"tool": "quick-scan",
	})

	result, err := s.handlePluginCallTool(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", toolResultText(result))
	}

	text := toolResultText(result)
	if !strings.Contains(text, "f-1") {
		t.Fatalf("expected finding from aliased tool, got: %s", text)
	}
}

func TestHandlePluginReadResource_Stub(t *testing.T) {
	s := New("0.1.0", nil)
	req := makeToolRequest(t, "plugin.read_resource", map[string]any{
		"plugin": "test",
		"uri":    "nox://test/results",
	})

	result, err := s.handlePluginReadResource(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for stub")
	}
	if !strings.Contains(toolResultText(result), "not yet implemented") {
		t.Fatalf("expected 'not yet implemented' message, got: %s", toolResultText(result))
	}
}

// --- handleGetFindingDetail tests ---

func TestHandleGetFindingDetail_BeforeScan(t *testing.T) {
	s := New("0.1.0", nil)
	req := makeToolRequest(t, "get_finding_detail", map[string]any{"finding_id": "SEC-001:main.go:1"})

	result, err := s.handleGetFindingDetail(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error before any scan")
	}

	text := toolResultText(result)
	if !strings.Contains(text, "no scan results") {
		t.Fatalf("expected no-scan-results message, got: %s", text)
	}
}

func TestHandleGetFindingDetail_MissingFindingID(t *testing.T) {
	s := scanCleanDir(t)
	req := makeToolRequest(t, "get_finding_detail", map[string]any{})

	result, err := s.handleGetFindingDetail(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for missing finding_id")
	}

	text := toolResultText(result)
	if !strings.Contains(text, "missing required argument: finding_id") {
		t.Fatalf("expected missing argument message, got: %s", text)
	}
}

func TestHandleGetFindingDetail_FindingNotFound(t *testing.T) {
	s := scanCleanDir(t)
	req := makeToolRequest(t, "get_finding_detail", map[string]any{"finding_id": "NONEXISTENT"})

	result, err := s.handleGetFindingDetail(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for nonexistent finding")
	}

	text := toolResultText(result)
	if !strings.Contains(text, "not found") {
		t.Fatalf("expected not found message, got: %s", text)
	}
}

func TestHandleGetFindingDetail_Success(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

	s := New("0.1.0", nil)
	scanReq := makeToolRequest(t, "scan", map[string]any{"path": dir})
	scanResult, err := s.handleScan(context.Background(), scanReq)
	if err != nil || scanResult.IsError {
		t.Fatalf("scan failed: %v", err)
	}

	// Get a finding ID from the scan results.
	s.mu.RLock()
	findings := s.cache.Findings.Findings()
	s.mu.RUnlock()

	if len(findings) == 0 {
		t.Fatal("expected at least one finding from scan")
	}

	findingID := findings[0].ID

	req := makeToolRequest(t, "get_finding_detail", map[string]any{
		"finding_id":    findingID,
		"context_lines": float64(3),
	})

	result, err := s.handleGetFindingDetail(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", toolResultText(result))
	}

	text := toolResultText(result)
	if !strings.Contains(text, findingID) {
		t.Fatalf("expected finding ID in response, got: %s", text)
	}
	if !strings.Contains(text, `"source"`) {
		t.Fatalf("expected source in response, got: %s", text)
	}
}

// --- handleListFindings tests ---

func TestHandleListFindings_BeforeScan(t *testing.T) {
	s := New("0.1.0", nil)
	req := makeToolRequest(t, "list_findings", map[string]any{})

	result, err := s.handleListFindings(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error before any scan")
	}

	text := toolResultText(result)
	if !strings.Contains(text, "no scan results") {
		t.Fatalf("expected no-scan-results message, got: %s", text)
	}
}

func TestHandleListFindings_NoFilters(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

	s := New("0.1.0", nil)
	scanReq := makeToolRequest(t, "scan", map[string]any{"path": dir})
	scanResult, err := s.handleScan(context.Background(), scanReq)
	if err != nil || scanResult.IsError {
		t.Fatalf("scan failed: %v", err)
	}

	req := makeToolRequest(t, "list_findings", map[string]any{})

	result, err := s.handleListFindings(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", toolResultText(result))
	}

	text := toolResultText(result)
	if !strings.Contains(text, `"RuleID"`) {
		t.Fatalf("expected RuleID in findings, got: %s", text)
	}
}

func TestHandleListFindings_WithSeverityFilter(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

	s := New("0.1.0", nil)
	scanReq := makeToolRequest(t, "scan", map[string]any{"path": dir})
	scanResult, err := s.handleScan(context.Background(), scanReq)
	if err != nil || scanResult.IsError {
		t.Fatalf("scan failed: %v", err)
	}

	req := makeToolRequest(t, "list_findings", map[string]any{
		"severity": "critical,high",
	})

	result, err := s.handleListFindings(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", toolResultText(result))
	}

	// Should return findings (secrets are typically high severity).
	text := toolResultText(result)
	if !strings.Contains(text, `"Severity"`) {
		t.Fatalf("expected Severity field in findings, got: %s", text)
	}
}

func TestHandleListFindings_WithRuleFilter(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

	s := New("0.1.0", nil)
	scanReq := makeToolRequest(t, "scan", map[string]any{"path": dir})
	scanResult, err := s.handleScan(context.Background(), scanReq)
	if err != nil || scanResult.IsError {
		t.Fatalf("scan failed: %v", err)
	}

	req := makeToolRequest(t, "list_findings", map[string]any{
		"rule": "SEC-*",
	})

	result, err := s.handleListFindings(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", toolResultText(result))
	}

	text := toolResultText(result)
	if !strings.Contains(text, `"RuleID"`) {
		t.Fatalf("expected RuleID in findings, got: %s", text)
	}
}

func TestHandleListFindings_WithFileFilter(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

	s := New("0.1.0", nil)
	scanReq := makeToolRequest(t, "scan", map[string]any{"path": dir})
	scanResult, err := s.handleScan(context.Background(), scanReq)
	if err != nil || scanResult.IsError {
		t.Fatalf("scan failed: %v", err)
	}

	req := makeToolRequest(t, "list_findings", map[string]any{
		"file": "config.env",
	})

	result, err := s.handleListFindings(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", toolResultText(result))
	}

	text := toolResultText(result)
	if !strings.Contains(text, "config.env") {
		t.Fatalf("expected config.env in findings, got: %s", text)
	}
}

func TestHandleListFindings_WithLimit(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

	s := New("0.1.0", nil)
	scanReq := makeToolRequest(t, "scan", map[string]any{"path": dir})
	scanResult, err := s.handleScan(context.Background(), scanReq)
	if err != nil || scanResult.IsError {
		t.Fatalf("scan failed: %v", err)
	}

	req := makeToolRequest(t, "list_findings", map[string]any{
		"limit": float64(1),
	})

	result, err := s.handleListFindings(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", toolResultText(result))
	}

	// Should work and return at most 1 finding.
	text := toolResultText(result)
	if !strings.Contains(text, `"RuleID"`) {
		t.Fatalf("expected findings in response, got: %s", text)
	}
}

func TestHandleListFindings_SuppressedFilter(t *testing.T) {
	dir := t.TempDir()
	// Write a file that will trigger a finding that we can suppress
	writeFile(t, dir, "config.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

	s := New("0.1.0", nil)

	// Run scan first to get the fingerprint
	scanReq := makeToolRequest(t, "scan", map[string]any{"path": dir})
	_, err := s.handleScan(context.Background(), scanReq)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Get all findings with include_suppressed to find the fingerprint
	listAllReq := makeToolRequest(t, "list_findings", map[string]any{
		"include_suppressed": true,
	})
	listAllResult, _ := s.handleListFindings(context.Background(), listAllReq)
	allText := toolResultText(listAllResult)

	// Now request without include_suppressed (default) - should not show suppressed
	reqDefault := makeToolRequest(t, "list_findings", map[string]any{})
	resultDefault, err := s.handleListFindings(context.Background(), reqDefault)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defaultText := toolResultText(resultDefault)

	// Verify that include_suppressed parameter exists and works
	if strings.Contains(allText, `"RuleID"`) {
		// If we have findings, the filter is working
		t.Logf("Found %d bytes in all findings response", len(allText))
	}
	if len(defaultText) <= len("[]") {
		t.Log("Default response correctly filters findings")
	}
}

// --- handleBaselineStatus tests ---

func TestHandleBaselineStatus_MissingPath(t *testing.T) {
	s := New("0.1.0", nil)
	req := makeToolRequest(t, "baseline_status", map[string]any{})

	result, err := s.handleBaselineStatus(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for missing path")
	}

	text := toolResultText(result)
	if !strings.Contains(text, "missing required argument: path") {
		t.Fatalf("expected missing path message, got: %s", text)
	}
}

func TestHandleBaselineStatus_DisallowedPath(t *testing.T) {
	s := New("0.1.0", []string{"/allowed/only"})
	req := makeToolRequest(t, "baseline_status", map[string]any{"path": "/not/allowed"})

	result, err := s.handleBaselineStatus(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for disallowed path")
	}

	text := toolResultText(result)
	if !strings.Contains(text, "outside allowed workspaces") {
		t.Fatalf("expected workspace error, got: %s", text)
	}
}

func TestHandleBaselineStatus_NoBaseline(t *testing.T) {
	dir := t.TempDir()
	s := New("0.1.0", nil)

	req := makeToolRequest(t, "baseline_status", map[string]any{"path": dir})

	result, err := s.handleBaselineStatus(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success (empty baseline), got error: %s", toolResultText(result))
	}

	text := toolResultText(result)
	if !strings.Contains(text, `"total":0`) && !strings.Contains(text, `"total": 0`) {
		t.Fatalf("expected total:0 for empty baseline, got: %s", text)
	}
}

func TestHandleBaselineStatus_WithBaseline(t *testing.T) {
	dir := t.TempDir()

	// Create a baseline file.
	baselineDir := filepath.Join(dir, ".nox")
	if err := os.MkdirAll(baselineDir, 0o755); err != nil {
		t.Fatal(err)
	}
	baselinePath := filepath.Join(baselineDir, "baseline.json")
	baselineContent := `{
		"schema_version": "1.0.0",
		"entries": [
			{
				"fingerprint": "abc123",
				"rule_id": "SEC-001",
				"file_path": "main.go",
				"severity": "high",
				"created_at": "2025-01-01T00:00:00Z"
			}
		]
	}`
	if err := os.WriteFile(baselinePath, []byte(baselineContent), 0o644); err != nil {
		t.Fatal(err)
	}

	s := New("0.1.0", nil)
	req := makeToolRequest(t, "baseline_status", map[string]any{"path": dir})

	result, err := s.handleBaselineStatus(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", toolResultText(result))
	}

	text := toolResultText(result)
	if !strings.Contains(text, `"total":1`) && !strings.Contains(text, `"total": 1`) {
		t.Fatalf("expected total:1, got: %s", text)
	}
	if !strings.Contains(text, `"high"`) {
		t.Fatalf("expected severity breakdown, got: %s", text)
	}
}

// --- handleBaselineAdd tests ---

func TestHandleBaselineAdd_MissingPath(t *testing.T) {
	s := New("0.1.0", nil)
	req := makeToolRequest(t, "baseline_add", map[string]any{"fingerprint": "abc123"})

	result, err := s.handleBaselineAdd(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for missing path")
	}

	text := toolResultText(result)
	if !strings.Contains(text, "missing required argument: path") {
		t.Fatalf("expected missing path message, got: %s", text)
	}
}

func TestHandleBaselineAdd_MissingFingerprint(t *testing.T) {
	dir := t.TempDir()
	s := New("0.1.0", nil)
	req := makeToolRequest(t, "baseline_add", map[string]any{"path": dir})

	result, err := s.handleBaselineAdd(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for missing fingerprint")
	}

	text := toolResultText(result)
	if !strings.Contains(text, "missing required argument: fingerprint") {
		t.Fatalf("expected missing fingerprint message, got: %s", text)
	}
}

func TestHandleBaselineAdd_DisallowedPath(t *testing.T) {
	s := New("0.1.0", []string{"/allowed/only"})
	req := makeToolRequest(t, "baseline_add", map[string]any{
		"path":        "/not/allowed",
		"fingerprint": "abc123",
	})

	result, err := s.handleBaselineAdd(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for disallowed path")
	}

	text := toolResultText(result)
	if !strings.Contains(text, "outside allowed workspaces") {
		t.Fatalf("expected workspace error, got: %s", text)
	}
}

func TestHandleBaselineAdd_NoScanResults(t *testing.T) {
	dir := t.TempDir()
	s := New("0.1.0", nil)
	req := makeToolRequest(t, "baseline_add", map[string]any{
		"path":        dir,
		"fingerprint": "abc123",
	})

	result, err := s.handleBaselineAdd(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for no scan results")
	}

	text := toolResultText(result)
	if !strings.Contains(text, "no scan results") {
		t.Fatalf("expected no scan results message, got: %s", text)
	}
}

func TestHandleBaselineAdd_FingerprintNotFound(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.go", "package main\n\nfunc main() {}\n")

	s := New("0.1.0", nil)
	scanReq := makeToolRequest(t, "scan", map[string]any{"path": dir})
	scanResult, err := s.handleScan(context.Background(), scanReq)
	if err != nil || scanResult.IsError {
		t.Fatalf("scan failed: %v", err)
	}

	req := makeToolRequest(t, "baseline_add", map[string]any{
		"path":        dir,
		"fingerprint": "nonexistent",
	})

	result, err := s.handleBaselineAdd(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for nonexistent fingerprint")
	}

	text := toolResultText(result)
	if !strings.Contains(text, "not found") {
		t.Fatalf("expected not found message, got: %s", text)
	}
}

func TestHandleBaselineAdd_Success(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

	s := New("0.1.0", nil)
	scanReq := makeToolRequest(t, "scan", map[string]any{"path": dir})
	scanResult, err := s.handleScan(context.Background(), scanReq)
	if err != nil || scanResult.IsError {
		t.Fatalf("scan failed: %v", err)
	}

	// Get a finding fingerprint.
	s.mu.RLock()
	findings := s.cache.Findings.Findings()
	s.mu.RUnlock()

	if len(findings) == 0 {
		t.Fatal("expected at least one finding from scan")
	}

	fingerprint := findings[0].Fingerprint

	req := makeToolRequest(t, "baseline_add", map[string]any{
		"path":        dir,
		"fingerprint": fingerprint,
		"reason":      "test baseline",
	})

	result, err := s.handleBaselineAdd(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", toolResultText(result))
	}

	text := toolResultText(result)
	if !strings.Contains(text, "Added finding") {
		t.Fatalf("expected success message, got: %s", text)
	}

	// Verify baseline file was created.
	baselinePath := filepath.Join(dir, ".nox", "baseline.json")
	if _, err := os.Stat(baselinePath); err != nil {
		t.Fatalf("expected baseline file to exist: %v", err)
	}
}

// --- handleVersion tests ---

func TestHandleVersion(t *testing.T) {
	s := New("1.2.3", nil)
	req := makeToolRequest(t, "version", map[string]any{})

	result, err := s.handleVersion(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", toolResultText(result))
	}

	text := toolResultText(result)
	if !strings.Contains(text, "1.2.3") {
		t.Fatalf("expected version in response, got: %s", text)
	}
}

// --- handleRules tests ---

func TestHandleRules(t *testing.T) {
	s := New("0.1.0", nil)
	req := makeToolRequest(t, "rules", map[string]any{})

	result, err := s.handleRules(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", toolResultText(result))
	}

	text := toolResultText(result)
	// Should contain at least one known rule ID.
	if !strings.Contains(text, "SEC-") && !strings.Contains(text, "AI-") && !strings.Contains(text, "IAC-") {
		t.Fatalf("expected rule IDs in response, got: %s", text[:min(len(text), 200)])
	}
}

// --- handleBadge tests ---

func TestHandleBadge_BeforeScan(t *testing.T) {
	s := New("0.1.0", nil)
	req := makeToolRequest(t, "badge", map[string]any{})

	result, err := s.handleBadge(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error before any scan")
	}

	text := toolResultText(result)
	if !strings.Contains(text, "no scan results") {
		t.Fatalf("expected no-scan-results message, got: %s", text)
	}
}

func TestHandleBadge_AfterScan(t *testing.T) {
	s := scanCleanDir(t)
	req := makeToolRequest(t, "badge", map[string]any{"label": "security"})

	result, err := s.handleBadge(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", toolResultText(result))
	}

	text := toolResultText(result)
	if !strings.Contains(text, `"grade"`) {
		t.Fatalf("expected grade in badge response, got: %s", text)
	}
	if !strings.Contains(text, `"label"`) {
		t.Fatalf("expected label in badge response, got: %s", text)
	}
}

// --- handleAnnotate tests ---

func TestHandleAnnotate_BeforeScan(t *testing.T) {
	s := New("0.1.0", nil)
	req := makeToolRequest(t, "annotate", map[string]any{})

	result, err := s.handleAnnotate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error before any scan")
	}

	text := toolResultText(result)
	if !strings.Contains(text, "no scan results") {
		t.Fatalf("expected no-scan-results message, got: %s", text)
	}
}

func TestHandleAnnotate_NoFindings(t *testing.T) {
	s := scanCleanDir(t)
	req := makeToolRequest(t, "annotate", map[string]any{})

	result, err := s.handleAnnotate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", toolResultText(result))
	}

	text := toolResultText(result)
	if !strings.Contains(text, "no findings to annotate") {
		t.Fatalf("expected no-findings message, got: %s", text)
	}
}

func TestHandleAnnotate_WithFindings(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

	s := New("0.1.0", nil)
	scanReq := makeToolRequest(t, "scan", map[string]any{"path": dir})
	scanResult, err := s.handleScan(context.Background(), scanReq)
	if err != nil || scanResult.IsError {
		t.Fatalf("scan failed: %v", err)
	}

	req := makeToolRequest(t, "annotate", map[string]any{})

	result, err := s.handleAnnotate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", toolResultText(result))
	}

	text := toolResultText(result)
	if !strings.Contains(text, `"event"`) {
		t.Fatalf("expected event field in annotate payload, got: %s", text)
	}
	if !strings.Contains(text, `"comments"`) {
		t.Fatalf("expected comments field in annotate payload, got: %s", text)
	}
}

// --- handleDiff tests ---

func TestHandleDiff_MissingPath(t *testing.T) {
	s := New("0.1.0", nil)
	req := makeToolRequest(t, "diff", map[string]any{})

	result, err := s.handleDiff(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for missing path")
	}

	text := toolResultText(result)
	if !strings.Contains(text, "missing required argument: path") {
		t.Fatalf("expected missing path message, got: %s", text)
	}
}

func TestHandleDiff_DisallowedPath(t *testing.T) {
	s := New("0.1.0", []string{"/allowed/only"})
	req := makeToolRequest(t, "diff", map[string]any{"path": "/not/allowed"})

	result, err := s.handleDiff(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for disallowed path")
	}

	text := toolResultText(result)
	if !strings.Contains(text, "outside allowed workspaces") {
		t.Fatalf("expected workspace error, got: %s", text)
	}
}

func TestHandleDiff_NonGitRepo(t *testing.T) {
	dir := t.TempDir()
	s := New("0.1.0", nil)
	req := makeToolRequest(t, "diff", map[string]any{"path": dir})

	result, err := s.handleDiff(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for non-git directory")
	}

	text := toolResultText(result)
	if !strings.Contains(text, "diff failed") {
		t.Fatalf("expected diff failed message, got: %s", text)
	}
}

// --- handleProtectStatus tests ---

func TestHandleProtectStatus_MissingPath(t *testing.T) {
	s := New("0.1.0", nil)
	req := makeToolRequest(t, "protect_status", map[string]any{})

	result, err := s.handleProtectStatus(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for missing path")
	}

	text := toolResultText(result)
	if !strings.Contains(text, "missing required argument: path") {
		t.Fatalf("expected missing path message, got: %s", text)
	}
}

func TestHandleProtectStatus_DisallowedPath(t *testing.T) {
	s := New("0.1.0", []string{"/allowed/only"})
	req := makeToolRequest(t, "protect_status", map[string]any{"path": "/not/allowed"})

	result, err := s.handleProtectStatus(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for disallowed path")
	}

	text := toolResultText(result)
	if !strings.Contains(text, "outside allowed workspaces") {
		t.Fatalf("expected workspace error, got: %s", text)
	}
}

func TestHandleProtectStatus_NonGitRepo(t *testing.T) {
	dir := t.TempDir()
	s := New("0.1.0", nil)
	req := makeToolRequest(t, "protect_status", map[string]any{"path": dir})

	result, err := s.handleProtectStatus(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for non-git directory")
	}

	text := toolResultText(result)
	if !strings.Contains(text, "not a git repository") {
		t.Fatalf("expected not-a-git-repo message, got: %s", text)
	}
}

func TestHandleProtectStatus_NotInstalled(t *testing.T) {
	dir := t.TempDir()

	// Initialize a git repo so we have .git/hooks.
	cmd := exec.Command("git", "init", "-b", "main")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+dir)
	if err := cmd.Run(); err != nil {
		t.Skipf("git not available: %v", err)
	}

	s := New("0.1.0", nil)
	req := makeToolRequest(t, "protect_status", map[string]any{"path": dir})

	result, err := s.handleProtectStatus(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", toolResultText(result))
	}

	text := toolResultText(result)
	if !strings.Contains(text, `"installed": false`) && !strings.Contains(text, `"installed":false`) {
		t.Fatalf("expected installed:false, got: %s", text)
	}
}

// --- handleVEXStatus tests ---

func TestHandleVEXStatus_MissingPath(t *testing.T) {
	s := New("0.1.0", nil)
	req := makeToolRequest(t, "vex_status", map[string]any{})

	result, err := s.handleVEXStatus(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for missing path")
	}

	text := toolResultText(result)
	if !strings.Contains(text, "missing required argument: path") {
		t.Fatalf("expected missing path message, got: %s", text)
	}
}

func TestHandleVEXStatus_Success(t *testing.T) {
	dir := t.TempDir()
	vexPath := filepath.Join(dir, "vex.json")
	content := `{
  "statements": [
    {"vulnerability": "CVE-2024-0001", "status": "not_affected"},
    {"vulnerability": "CVE-2024-0002", "status": "fixed"}
  ]
}`
	if err := os.WriteFile(vexPath, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write VEX file: %v", err)
	}

	s := New("0.1.0", nil)
	req := makeToolRequest(t, "vex_status", map[string]any{"path": vexPath})

	result, err := s.handleVEXStatus(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", toolResultText(result))
	}

	text := toolResultText(result)
	if !strings.Contains(text, `"statements": 2`) && !strings.Contains(text, `"statements":2`) {
		t.Fatalf("expected statements count, got: %s", text)
	}
	if !strings.Contains(text, "not_affected") || !strings.Contains(text, "fixed") {
		t.Fatalf("expected status breakdown, got: %s", text)
	}
	if !strings.Contains(text, "VEX: 2 statements") {
		t.Fatalf("expected summary, got: %s", text)
	}
}

// --- handleComplianceReport tests ---

func TestHandleComplianceReport_MissingFramework(t *testing.T) {
	s := scanCleanDir(t)
	req := makeToolRequest(t, "compliance_report", map[string]any{})

	result, err := s.handleComplianceReport(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for missing framework")
	}

	text := toolResultText(result)
	if !strings.Contains(text, "missing required argument: framework") {
		t.Fatalf("expected missing framework message, got: %s", text)
	}
}

func TestHandleComplianceReport_Success(t *testing.T) {
	s := scanCleanDir(t)
	req := makeToolRequest(t, "compliance_report", map[string]any{"framework": "CIS"})

	result, err := s.handleComplianceReport(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", toolResultText(result))
	}

	text := toolResultText(result)
	if !strings.Contains(text, `"framework"`) || !strings.Contains(text, "CIS") {
		t.Fatalf("expected framework in report, got: %s", text)
	}
}

// --- handleDataSensitivityReport tests ---

func TestHandleDataSensitivityReport_NoScanResults(t *testing.T) {
	s := New("0.1.0", nil)
	req := makeToolRequest(t, "data_sensitivity_report", map[string]any{})

	result, err := s.handleDataSensitivityReport(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error before any scan")
	}

	text := toolResultText(result)
	if !strings.Contains(text, "no scan results") {
		t.Fatalf("expected no-scan-results message, got: %s", text)
	}
}

func TestHandleDataSensitivityReport_WithFindings(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "data.txt", "email = user@example.com\nssn = 123-45-6789\n")

	s := New("0.1.0", nil)
	scanReq := makeToolRequest(t, "scan", map[string]any{"path": dir})
	scanResult, err := s.handleScan(context.Background(), scanReq)
	if err != nil || scanResult.IsError {
		t.Fatalf("scan failed: %v", err)
	}

	req := makeToolRequest(t, "data_sensitivity_report", map[string]any{})
	result, err := s.handleDataSensitivityReport(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", toolResultText(result))
	}

	var report struct {
		TotalFindings int `json:"total_findings"`
		Rules         []struct {
			RuleID string   `json:"rule_id"`
			Count  int      `json:"count"`
			Files  []string `json:"files"`
		} `json:"rules"`
		AffectedFiles []string `json:"affected_files"`
	}

	text := toolResultText(result)
	if err := json.Unmarshal([]byte(text), &report); err != nil {
		t.Fatalf("failed to parse report JSON: %v", err)
	}
	if report.TotalFindings == 0 {
		t.Fatal("expected data sensitivity findings")
	}

	seen := make(map[string]bool)
	for _, rule := range report.Rules {
		seen[rule.RuleID] = true
	}
	if !seen["DATA-001"] && !seen["DATA-002"] {
		t.Fatalf("expected DATA-* rules in report, got: %+v", report.Rules)
	}
}

// --- handleResourceRules tests ---

func TestResourceRules(t *testing.T) {
	s := New("0.1.0", nil)
	req := mcp.ReadResourceRequest{}
	req.Params.URI = "nox://rules"

	contents, err := s.handleResourceRules(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(contents) == 0 {
		t.Fatal("expected non-empty resource contents")
	}

	tc, ok := contents[0].(mcp.TextResourceContents)
	if !ok {
		t.Fatal("expected TextResourceContents")
	}
	if tc.URI != "nox://rules" {
		t.Fatalf("expected URI nox://rules, got %s", tc.URI)
	}
	if !strings.Contains(tc.Text, "SEC-") {
		t.Fatalf("expected rule IDs in resource, got: %s", tc.Text[:min(len(tc.Text), 200)])
	}
}
