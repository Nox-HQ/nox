package server

import (
	"context"
	"encoding/json"
	"net"
	"os"
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
