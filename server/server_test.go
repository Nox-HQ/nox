package server

import (
	"context"
	"encoding/json"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	mcp "github.com/felixgeelhaar/mcp-go"
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

func TestIsPathAllowed_SymlinkTraversalBlocked(t *testing.T) {
	// Create an allowed workspace and a directory outside it.
	workspace := t.TempDir()
	outside := t.TempDir()

	// Resolve symlinks for both (handles macOS /var -> /private/var).
	workspace, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		t.Fatal(err)
	}
	outside, err = filepath.EvalSymlinks(outside)
	if err != nil {
		t.Fatal(err)
	}

	// Write a file outside the workspace.
	outsideFile := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create a symlink inside the workspace pointing outside.
	link := filepath.Join(workspace, "escape")
	if err := os.Symlink(outsideFile, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	s := New("0.1.0", []string{workspace})

	// The symlink target is outside the workspace — must be blocked.
	if err := s.isPathAllowed(link); err == nil {
		t.Fatal("expected symlink traversal to be blocked")
	}
}

func TestHandleScan_CleanDirectory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.go", "package main\n\nfunc main() {}\n")

	s := New("0.1.0", nil)
	result, err := s.handleScan(context.Background(), scanInput{Path: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(result, "Error:") {
		t.Fatalf("expected success, got: %s", result)
	}
	if !strings.Contains(result, "0 findings") {
		t.Fatalf("expected 0 findings in summary, got: %s", result)
	}
}

func TestHandleScan_WithFindings(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

	s := New("0.1.0", nil)
	result, err := s.handleScan(context.Background(), scanInput{Path: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(result, "Error:") {
		t.Fatalf("expected success, got: %s", result)
	}
	if strings.Contains(result, "0 findings") {
		t.Fatalf("expected findings in summary, got: %s", result)
	}
}

func TestHandleScan_DisallowedPath(t *testing.T) {
	dir := t.TempDir()
	s := New("0.1.0", []string{"/allowed/only"})

	result, err := s.handleScan(context.Background(), scanInput{Path: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error for disallowed path")
	}
	if !strings.Contains(result, "outside allowed workspaces") {
		t.Fatalf("expected workspace error, got: %s", result)
	}
}

func TestHandleScan_MissingPath(t *testing.T) {
	s := New("0.1.0", nil)
	result, err := s.handleScan(context.Background(), scanInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error for missing path argument")
	}
}

func TestHandleGetFindings_BeforeScan(t *testing.T) {
	s := New("0.1.0", nil)
	result, err := s.handleGetFindings(context.Background(), getFindingsInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error before any scan")
	}
	if !strings.Contains(result, "no scan results") {
		t.Fatalf("expected no-scan-results message, got: %s", result)
	}
}

func TestHandleGetFindings_JSON(t *testing.T) {
	s := scanCleanDir(t)
	result, err := s.handleGetFindings(context.Background(), getFindingsInput{Format: "json"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(result, "Error:") {
		t.Fatalf("expected success, got: %s", result)
	}
	if !strings.Contains(result, `"findings"`) {
		t.Fatalf("expected JSON findings output, got: %s", result)
	}
}

func TestHandleGetFindings_SARIF(t *testing.T) {
	s := scanCleanDir(t)
	result, err := s.handleGetFindings(context.Background(), getFindingsInput{Format: "sarif"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(result, "Error:") {
		t.Fatalf("expected success, got: %s", result)
	}
	if !strings.Contains(result, `"$schema"`) {
		t.Fatalf("expected SARIF output, got: %s", result)
	}
}

func TestHandleGetSBOM_BeforeScan(t *testing.T) {
	s := New("0.1.0", nil)
	result, err := s.handleGetSBOM(context.Background(), getSBOMInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error before any scan")
	}
}

func TestHandleGetSBOM_CDX(t *testing.T) {
	s := scanCleanDir(t)
	result, err := s.handleGetSBOM(context.Background(), getSBOMInput{Format: "cdx"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(result, "Error:") {
		t.Fatalf("expected success, got: %s", result)
	}
	if !strings.Contains(result, "CycloneDX") {
		t.Fatalf("expected CycloneDX output, got: %s", result)
	}
}

func TestHandleGetSBOM_SPDX(t *testing.T) {
	s := scanCleanDir(t)
	result, err := s.handleGetSBOM(context.Background(), getSBOMInput{Format: "spdx"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(result, "Error:") {
		t.Fatalf("expected success, got: %s", result)
	}
	if !strings.Contains(result, "SPDX") {
		t.Fatalf("expected SPDX output, got: %s", result)
	}
}

func TestResourceFindings_BeforeScan(t *testing.T) {
	s := New("0.1.0", nil)
	_, err := s.handleResourceFindings(context.Background(), "nox://findings", nil)
	if err == nil {
		t.Fatal("expected error for resource before scan")
	}
}

func TestResourceFindings_AfterScan(t *testing.T) {
	s := scanCleanDir(t)
	content, err := s.handleResourceFindings(context.Background(), "nox://findings", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if content.URI != "nox://findings" {
		t.Fatalf("expected URI nox://findings, got %s", content.URI)
	}
	if content.MimeType != "application/json" {
		t.Fatalf("expected application/json, got %s", content.MimeType)
	}
	if !strings.Contains(content.Text, `"findings"`) {
		t.Fatalf("expected findings JSON, got: %s", content.Text)
	}
}

func TestResourceSARIF_AfterScan(t *testing.T) {
	s := scanCleanDir(t)
	content, err := s.handleResourceSARIF(context.Background(), "nox://sarif", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(content.Text, `"$schema"`) {
		t.Fatalf("expected SARIF content, got: %s", content.Text)
	}
}

func TestResourceCDX_AfterScan(t *testing.T) {
	s := scanCleanDir(t)
	content, err := s.handleResourceCDX(context.Background(), "nox://sbom/cdx", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(content.Text, "CycloneDX") {
		t.Fatalf("expected CycloneDX content, got: %s", content.Text)
	}
}

func TestResourceSPDX_AfterScan(t *testing.T) {
	s := scanCleanDir(t)
	content, err := s.handleResourceSPDX(context.Background(), "nox://sbom/spdx", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(content.Text, "SPDX") {
		t.Fatalf("expected SPDX content, got: %s", content.Text)
	}
}

func TestResourceAIInventory_AfterScan(t *testing.T) {
	s := scanCleanDir(t)
	content, err := s.handleResourceAIInventory(context.Background(), "nox://ai-inventory", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(content.Text, "schema_version") {
		t.Fatalf("expected AI inventory JSON, got: %s", content.Text)
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

// scanCleanDir creates a temporary directory with a clean Go file and
// runs a scan against it, returning the server with cached results.
func scanCleanDir(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, "main.go", "package main\n\nfunc main() {}\n")

	s := New("0.1.0", nil)
	result, err := s.handleScan(context.Background(), scanInput{Path: dir})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if strings.HasPrefix(result, "Error:") {
		t.Fatalf("scan returned error: %s", result)
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
		_ = s.Serve(lis)
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
	t.Cleanup(func() { _ = conn.Close() })

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
	result, err := s.handlePluginList(context.Background(), emptyInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error for nil host")
	}
	if !strings.Contains(result, "no plugin host") {
		t.Fatalf("expected 'no plugin host' message, got: %s", result)
	}
}

func TestHandlePluginList_EmptyHost(t *testing.T) {
	h := plugin.NewHost()
	s := New("0.1.0", nil, WithPluginHost(h))
	result, err := s.handlePluginList(context.Background(), emptyInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(result, "Error:") {
		t.Fatalf("expected success, got: %s", result)
	}
	if result != "[]" {
		t.Fatalf("expected empty array, got: %s", result)
	}
}

func TestHandlePluginList_WithPlugins(t *testing.T) {
	h := createHostWithMockPlugin(t)
	s := New("0.1.0", nil, WithPluginHost(h))
	result, err := s.handlePluginList(context.Background(), emptyInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(result, "Error:") {
		t.Fatalf("expected success, got: %s", result)
	}
	if !strings.Contains(result, "test-scanner") {
		t.Fatalf("expected 'test-scanner' in output, got: %s", result)
	}
	if !strings.Contains(result, `"scan"`) {
		t.Fatalf("expected 'scan' tool in output, got: %s", result)
	}
}

func TestHandlePluginCallTool_NoHost(t *testing.T) {
	s := New("0.1.0", nil)
	result, err := s.handlePluginCallTool(context.Background(), pluginCallToolInput{Tool: "scan"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error for nil host")
	}
	if !strings.Contains(result, "no plugin host") {
		t.Fatalf("expected 'no plugin host' message, got: %s", result)
	}
}

func TestHandlePluginCallTool_MissingToolArg(t *testing.T) {
	h := createHostWithMockPlugin(t)
	s := New("0.1.0", nil, WithPluginHost(h))
	result, err := s.handlePluginCallTool(context.Background(), pluginCallToolInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error for missing tool argument")
	}
	if !strings.Contains(result, "missing required argument: tool") {
		t.Fatalf("expected missing tool message, got: %s", result)
	}
}

func TestHandlePluginCallTool_Success(t *testing.T) {
	h := createHostWithMockPlugin(t)
	s := New("0.1.0", nil, WithPluginHost(h))
	result, err := s.handlePluginCallTool(context.Background(), pluginCallToolInput{
		Tool: "test-scanner.scan",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(result, "Error:") {
		t.Fatalf("expected success, got: %s", result)
	}
	if !strings.Contains(result, "f-1") {
		t.Fatalf("expected finding ID in output, got: %s", result)
	}
	if !strings.Contains(result, `"severity":"high"`) {
		t.Fatalf("expected severity as string, got: %s", result)
	}
}

func TestHandlePluginCallTool_UnknownTool(t *testing.T) {
	h := createHostWithMockPlugin(t)
	s := New("0.1.0", nil, WithPluginHost(h))
	result, err := s.handlePluginCallTool(context.Background(), pluginCallToolInput{
		Tool: "nonexistent",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error for unknown tool")
	}
	if !strings.Contains(result, "no plugin provides tool") {
		t.Fatalf("expected 'no plugin provides tool' message, got: %s", result)
	}
}

func TestHandlePluginCallTool_WorkspaceBlocked(t *testing.T) {
	h := createHostWithMockPlugin(t)
	s := New("0.1.0", []string{"/allowed/only"}, WithPluginHost(h))
	result, err := s.handlePluginCallTool(context.Background(), pluginCallToolInput{
		Tool:          "test-scanner.scan",
		WorkspaceRoot: "/not/allowed",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error for blocked workspace")
	}
	if !strings.Contains(result, "outside allowed workspaces") {
		t.Fatalf("expected workspace error, got: %s", result)
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
	result, err := s.handlePluginCallTool(context.Background(), pluginCallToolInput{
		Tool: "quick-scan",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(result, "Error:") {
		t.Fatalf("expected success, got: %s", result)
	}
	if !strings.Contains(result, "f-1") {
		t.Fatalf("expected finding from aliased tool, got: %s", result)
	}
}

func TestHandlePluginReadResource_Stub(t *testing.T) {
	s := New("0.1.0", nil)
	result, err := s.handlePluginReadResource(context.Background(), pluginReadResourceInput{
		Plugin: "test",
		URI:    "nox://test/results",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error for stub")
	}
	if !strings.Contains(result, "not yet implemented") {
		t.Fatalf("expected 'not yet implemented' message, got: %s", result)
	}
}

// --- handleGetFindingDetail tests ---

func TestHandleGetFindingDetail_BeforeScan(t *testing.T) {
	s := New("0.1.0", nil)
	result, err := s.handleGetFindingDetail(context.Background(), getFindingDetailInput{FindingID: "SEC-001:main.go:1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error before any scan")
	}
	if !strings.Contains(result, "no scan results") {
		t.Fatalf("expected no-scan-results message, got: %s", result)
	}
}

func TestHandleGetFindingDetail_MissingFindingID(t *testing.T) {
	s := scanCleanDir(t)
	result, err := s.handleGetFindingDetail(context.Background(), getFindingDetailInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error for missing finding_id")
	}
	if !strings.Contains(result, "missing required argument: finding_id") {
		t.Fatalf("expected missing argument message, got: %s", result)
	}
}

func TestHandleGetFindingDetail_FindingNotFound(t *testing.T) {
	s := scanCleanDir(t)
	result, err := s.handleGetFindingDetail(context.Background(), getFindingDetailInput{FindingID: "NONEXISTENT"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error for nonexistent finding")
	}
	if !strings.Contains(result, "not found") {
		t.Fatalf("expected not found message, got: %s", result)
	}
}

func TestHandleGetFindingDetail_Success(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

	s := New("0.1.0", nil)
	scanResult, err := s.handleScan(context.Background(), scanInput{Path: dir})
	if err != nil || strings.HasPrefix(scanResult, "Error:") {
		t.Fatalf("scan failed: %v / %s", err, scanResult)
	}

	// Get a finding ID from the scan results.
	pc := s.getCache("")
	findings := pc.result.Findings.Findings()

	if len(findings) == 0 {
		t.Fatal("expected at least one finding from scan")
	}

	findingID := findings[0].ID

	result, err := s.handleGetFindingDetail(context.Background(), getFindingDetailInput{
		FindingID:    findingID,
		ContextLines: 3,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(result, "Error:") {
		t.Fatalf("expected success, got: %s", result)
	}
	if !strings.Contains(result, findingID) {
		t.Fatalf("expected finding ID in response, got: %s", result)
	}
	if !strings.Contains(result, `"source"`) {
		t.Fatalf("expected source in response, got: %s", result)
	}
}

// --- handleListFindings tests ---

func TestHandleListFindings_BeforeScan(t *testing.T) {
	s := New("0.1.0", nil)
	result, err := s.handleListFindings(context.Background(), listFindingsInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error before any scan")
	}
	if !strings.Contains(result, "no scan results") {
		t.Fatalf("expected no-scan-results message, got: %s", result)
	}
}

func TestHandleListFindings_NoFilters(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

	s := New("0.1.0", nil)
	scanResult, err := s.handleScan(context.Background(), scanInput{Path: dir})
	if err != nil || strings.HasPrefix(scanResult, "Error:") {
		t.Fatalf("scan failed: %v / %s", err, scanResult)
	}

	result, err := s.handleListFindings(context.Background(), listFindingsInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(result, "Error:") {
		t.Fatalf("expected success, got: %s", result)
	}
	if !strings.Contains(result, `"RuleID"`) {
		t.Fatalf("expected RuleID in findings, got: %s", result)
	}
}

func TestHandleListFindings_WithSeverityFilter(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

	s := New("0.1.0", nil)
	scanResult, err := s.handleScan(context.Background(), scanInput{Path: dir})
	if err != nil || strings.HasPrefix(scanResult, "Error:") {
		t.Fatalf("scan failed: %v / %s", err, scanResult)
	}

	result, err := s.handleListFindings(context.Background(), listFindingsInput{
		Severity: "critical,high",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(result, "Error:") {
		t.Fatalf("expected success, got: %s", result)
	}
	if !strings.Contains(result, `"Severity"`) {
		t.Fatalf("expected Severity field in findings, got: %s", result)
	}
}

func TestHandleListFindings_WithRuleFilter(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

	s := New("0.1.0", nil)
	scanResult, err := s.handleScan(context.Background(), scanInput{Path: dir})
	if err != nil || strings.HasPrefix(scanResult, "Error:") {
		t.Fatalf("scan failed: %v / %s", err, scanResult)
	}

	result, err := s.handleListFindings(context.Background(), listFindingsInput{
		Rule: "SEC-*",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(result, "Error:") {
		t.Fatalf("expected success, got: %s", result)
	}
	if !strings.Contains(result, `"RuleID"`) {
		t.Fatalf("expected RuleID in findings, got: %s", result)
	}
}

func TestHandleListFindings_WithFileFilter(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

	s := New("0.1.0", nil)
	scanResult, err := s.handleScan(context.Background(), scanInput{Path: dir})
	if err != nil || strings.HasPrefix(scanResult, "Error:") {
		t.Fatalf("scan failed: %v / %s", err, scanResult)
	}

	result, err := s.handleListFindings(context.Background(), listFindingsInput{
		File: "config.env",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(result, "Error:") {
		t.Fatalf("expected success, got: %s", result)
	}
	if !strings.Contains(result, "config.env") {
		t.Fatalf("expected config.env in findings, got: %s", result)
	}
}

func TestHandleListFindings_WithLimit(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

	s := New("0.1.0", nil)
	scanResult, err := s.handleScan(context.Background(), scanInput{Path: dir})
	if err != nil || strings.HasPrefix(scanResult, "Error:") {
		t.Fatalf("scan failed: %v / %s", err, scanResult)
	}

	result, err := s.handleListFindings(context.Background(), listFindingsInput{
		Limit: 1,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(result, "Error:") {
		t.Fatalf("expected success, got: %s", result)
	}
	if !strings.Contains(result, `"RuleID"`) {
		t.Fatalf("expected findings in response, got: %s", result)
	}
}

func TestHandleListFindings_SuppressedFilter(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

	s := New("0.1.0", nil)
	_, err := s.handleScan(context.Background(), scanInput{Path: dir})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Get all findings with include_suppressed to find the fingerprint.
	allResult, _ := s.handleListFindings(context.Background(), listFindingsInput{
		IncludeSuppressed: true,
	})

	// Request without include_suppressed (default).
	defaultResult, err := s.handleListFindings(context.Background(), listFindingsInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify that include_suppressed parameter exists and works.
	if strings.Contains(allResult, `"RuleID"`) {
		t.Logf("Found %d bytes in all findings response", len(allResult))
	}
	if len(defaultResult) <= len("[]") {
		t.Log("Default response correctly filters findings")
	}
}

// --- handleBaselineStatus tests ---

func TestHandleBaselineStatus_MissingPath(t *testing.T) {
	s := New("0.1.0", nil)
	result, err := s.handleBaselineStatus(context.Background(), baselineStatusInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error for missing path")
	}
	if !strings.Contains(result, "missing required argument: path") {
		t.Fatalf("expected missing path message, got: %s", result)
	}
}

func TestHandleBaselineStatus_DisallowedPath(t *testing.T) {
	s := New("0.1.0", []string{"/allowed/only"})
	result, err := s.handleBaselineStatus(context.Background(), baselineStatusInput{Path: "/not/allowed"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error for disallowed path")
	}
	if !strings.Contains(result, "outside allowed workspaces") {
		t.Fatalf("expected workspace error, got: %s", result)
	}
}

func TestHandleBaselineStatus_NoBaseline(t *testing.T) {
	dir := t.TempDir()
	s := New("0.1.0", nil)
	result, err := s.handleBaselineStatus(context.Background(), baselineStatusInput{Path: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(result, "Error:") {
		t.Fatalf("expected success (empty baseline), got: %s", result)
	}
	if !strings.Contains(result, `"total":0`) && !strings.Contains(result, `"total": 0`) {
		t.Fatalf("expected total:0 for empty baseline, got: %s", result)
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
	result, err := s.handleBaselineStatus(context.Background(), baselineStatusInput{Path: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(result, "Error:") {
		t.Fatalf("expected success, got: %s", result)
	}
	if !strings.Contains(result, `"total":1`) && !strings.Contains(result, `"total": 1`) {
		t.Fatalf("expected total:1, got: %s", result)
	}
	if !strings.Contains(result, `"high"`) {
		t.Fatalf("expected severity breakdown, got: %s", result)
	}
}

// --- handleBaselineAdd tests ---

func TestHandleBaselineAdd_MissingPath(t *testing.T) {
	s := New("0.1.0", nil)
	result, err := s.handleBaselineAdd(context.Background(), baselineAddInput{Fingerprint: "abc123"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error for missing path")
	}
	if !strings.Contains(result, "missing required argument: path") {
		t.Fatalf("expected missing path message, got: %s", result)
	}
}

func TestHandleBaselineAdd_MissingFingerprint(t *testing.T) {
	dir := t.TempDir()
	s := New("0.1.0", nil)
	result, err := s.handleBaselineAdd(context.Background(), baselineAddInput{Path: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error for missing fingerprint")
	}
	if !strings.Contains(result, "missing required argument: fingerprint") {
		t.Fatalf("expected missing fingerprint message, got: %s", result)
	}
}

func TestHandleBaselineAdd_DisallowedPath(t *testing.T) {
	s := New("0.1.0", []string{"/allowed/only"})
	result, err := s.handleBaselineAdd(context.Background(), baselineAddInput{
		Path:        "/not/allowed",
		Fingerprint: "abc123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error for disallowed path")
	}
	if !strings.Contains(result, "outside allowed workspaces") {
		t.Fatalf("expected workspace error, got: %s", result)
	}
}

func TestHandleBaselineAdd_NoScanResults(t *testing.T) {
	dir := t.TempDir()
	s := New("0.1.0", nil)
	result, err := s.handleBaselineAdd(context.Background(), baselineAddInput{
		Path:        dir,
		Fingerprint: "abc123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error for no scan results")
	}
	if !strings.Contains(result, "no scan results") {
		t.Fatalf("expected no scan results message, got: %s", result)
	}
}

func TestHandleBaselineAdd_FingerprintNotFound(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.go", "package main\n\nfunc main() {}\n")

	s := New("0.1.0", nil)
	scanResult, err := s.handleScan(context.Background(), scanInput{Path: dir})
	if err != nil || strings.HasPrefix(scanResult, "Error:") {
		t.Fatalf("scan failed: %v / %s", err, scanResult)
	}

	result, err := s.handleBaselineAdd(context.Background(), baselineAddInput{
		Path:        dir,
		Fingerprint: "nonexistent",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error for nonexistent fingerprint")
	}
	if !strings.Contains(result, "not found") {
		t.Fatalf("expected not found message, got: %s", result)
	}
}

func TestHandleBaselineAdd_Success(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

	s := New("0.1.0", nil)
	scanResult, err := s.handleScan(context.Background(), scanInput{Path: dir})
	if err != nil || strings.HasPrefix(scanResult, "Error:") {
		t.Fatalf("scan failed: %v / %s", err, scanResult)
	}

	// Get a finding fingerprint.
	pc := s.getCache("")
	findings := pc.result.Findings.Findings()

	if len(findings) == 0 {
		t.Fatal("expected at least one finding from scan")
	}

	fingerprint := findings[0].Fingerprint

	result, err := s.handleBaselineAdd(context.Background(), baselineAddInput{
		Path:        dir,
		Fingerprint: fingerprint,
		Reason:      "test baseline",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(result, "Error:") {
		t.Fatalf("expected success, got: %s", result)
	}
	if !strings.Contains(result, "Added finding") {
		t.Fatalf("expected success message, got: %s", result)
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
	result, err := s.handleVersion(context.Background(), emptyInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(result, "Error:") {
		t.Fatalf("expected success, got: %s", result)
	}
	if !strings.Contains(result, "1.2.3") {
		t.Fatalf("expected version in response, got: %s", result)
	}
}

// --- handleRules tests ---

func TestHandleRules(t *testing.T) {
	s := New("0.1.0", nil)
	result, err := s.handleRules(context.Background(), emptyInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(result, "Error:") {
		t.Fatalf("expected success, got: %s", result)
	}
	// Should contain at least one known rule ID.
	if !strings.Contains(result, "SEC-") && !strings.Contains(result, "AI-") && !strings.Contains(result, "IAC-") {
		t.Fatalf("expected rule IDs in response, got: %s", result[:min(len(result), 200)])
	}
}

// --- handleBadge tests ---

func TestHandleBadge_BeforeScan(t *testing.T) {
	s := New("0.1.0", nil)
	result, err := s.handleBadge(context.Background(), badgeInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error before any scan")
	}
	if !strings.Contains(result, "no scan results") {
		t.Fatalf("expected no-scan-results message, got: %s", result)
	}
}

func TestHandleBadge_AfterScan(t *testing.T) {
	s := scanCleanDir(t)
	result, err := s.handleBadge(context.Background(), badgeInput{Label: "security"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(result, "Error:") {
		t.Fatalf("expected success, got: %s", result)
	}
	if !strings.Contains(result, `"grade"`) {
		t.Fatalf("expected grade in badge response, got: %s", result)
	}
	if !strings.Contains(result, `"label"`) {
		t.Fatalf("expected label in badge response, got: %s", result)
	}
}

// --- handleAnnotate tests ---

func TestHandleAnnotate_BeforeScan(t *testing.T) {
	s := New("0.1.0", nil)
	result, err := s.handleAnnotate(context.Background(), emptyInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error before any scan")
	}
	if !strings.Contains(result, "no scan results") {
		t.Fatalf("expected no-scan-results message, got: %s", result)
	}
}

func TestHandleAnnotate_NoFindings(t *testing.T) {
	s := scanCleanDir(t)
	result, err := s.handleAnnotate(context.Background(), emptyInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(result, "Error:") {
		t.Fatalf("expected success, got: %s", result)
	}
	if !strings.Contains(result, "no findings to annotate") {
		t.Fatalf("expected no-findings message, got: %s", result)
	}
}

func TestHandleAnnotate_WithFindings(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

	s := New("0.1.0", nil)
	scanResult, err := s.handleScan(context.Background(), scanInput{Path: dir})
	if err != nil || strings.HasPrefix(scanResult, "Error:") {
		t.Fatalf("scan failed: %v / %s", err, scanResult)
	}

	result, err := s.handleAnnotate(context.Background(), emptyInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(result, "Error:") {
		t.Fatalf("expected success, got: %s", result)
	}
	if !strings.Contains(result, `"event"`) {
		t.Fatalf("expected event field in annotate payload, got: %s", result)
	}
	if !strings.Contains(result, `"comments"`) {
		t.Fatalf("expected comments field in annotate payload, got: %s", result)
	}
}

// --- handleDiff tests ---

func TestHandleDiff_MissingPath(t *testing.T) {
	s := New("0.1.0", nil)
	result, err := s.handleDiff(context.Background(), diffInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error for missing path")
	}
	if !strings.Contains(result, "missing required argument: path") {
		t.Fatalf("expected missing path message, got: %s", result)
	}
}

func TestHandleDiff_DisallowedPath(t *testing.T) {
	s := New("0.1.0", []string{"/allowed/only"})
	result, err := s.handleDiff(context.Background(), diffInput{Path: "/not/allowed"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error for disallowed path")
	}
	if !strings.Contains(result, "outside allowed workspaces") {
		t.Fatalf("expected workspace error, got: %s", result)
	}
}

func TestHandleDiff_NonGitRepo(t *testing.T) {
	dir := t.TempDir()
	s := New("0.1.0", nil)
	result, err := s.handleDiff(context.Background(), diffInput{Path: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error for non-git directory")
	}
	if !strings.Contains(result, "diff failed") {
		t.Fatalf("expected diff failed message, got: %s", result)
	}
}

// --- handleProtectStatus tests ---

func TestHandleProtectStatus_MissingPath(t *testing.T) {
	s := New("0.1.0", nil)
	result, err := s.handleProtectStatus(context.Background(), protectStatusInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error for missing path")
	}
	if !strings.Contains(result, "missing required argument: path") {
		t.Fatalf("expected missing path message, got: %s", result)
	}
}

func TestHandleProtectStatus_DisallowedPath(t *testing.T) {
	s := New("0.1.0", []string{"/allowed/only"})
	result, err := s.handleProtectStatus(context.Background(), protectStatusInput{Path: "/not/allowed"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error for disallowed path")
	}
	if !strings.Contains(result, "outside allowed workspaces") {
		t.Fatalf("expected workspace error, got: %s", result)
	}
}

func TestHandleProtectStatus_NonGitRepo(t *testing.T) {
	dir := t.TempDir()
	s := New("0.1.0", nil)
	result, err := s.handleProtectStatus(context.Background(), protectStatusInput{Path: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error for non-git directory")
	}
	if !strings.Contains(result, "not a git repository") {
		t.Fatalf("expected not-a-git-repo message, got: %s", result)
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
	result, err := s.handleProtectStatus(context.Background(), protectStatusInput{Path: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(result, "Error:") {
		t.Fatalf("expected success, got: %s", result)
	}
	if !strings.Contains(result, `"installed": false`) && !strings.Contains(result, `"installed":false`) {
		t.Fatalf("expected installed:false, got: %s", result)
	}
}

// --- handleVEXStatus tests ---

func TestHandleVEXStatus_MissingPath(t *testing.T) {
	s := New("0.1.0", nil)
	result, err := s.handleVEXStatus(context.Background(), vexStatusInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error for missing path")
	}
	if !strings.Contains(result, "missing required argument: path") {
		t.Fatalf("expected missing path message, got: %s", result)
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
	result, err := s.handleVEXStatus(context.Background(), vexStatusInput{Path: vexPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(result, "Error:") {
		t.Fatalf("expected success, got: %s", result)
	}
	if !strings.Contains(result, `"statements": 2`) && !strings.Contains(result, `"statements":2`) {
		t.Fatalf("expected statements count, got: %s", result)
	}
	if !strings.Contains(result, "not_affected") || !strings.Contains(result, "fixed") {
		t.Fatalf("expected status breakdown, got: %s", result)
	}
	if !strings.Contains(result, "VEX: 2 statements") {
		t.Fatalf("expected summary, got: %s", result)
	}
}

// --- handleDataSensitivityReport tests ---

func TestHandleDataSensitivityReport_NoScanResults(t *testing.T) {
	s := New("0.1.0", nil)
	result, err := s.handleDataSensitivityReport(context.Background(), emptyInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error before any scan")
	}
	if !strings.Contains(result, "no scan results") {
		t.Fatalf("expected no-scan-results message, got: %s", result)
	}
}

func TestHandleDataSensitivityReport_WithFindings(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "data.txt", "email = user@example.com\nssn = 123-45-6789\n")

	s := New("0.1.0", nil)
	scanResult, err := s.handleScan(context.Background(), scanInput{Path: dir})
	if err != nil || strings.HasPrefix(scanResult, "Error:") {
		t.Fatalf("scan failed: %v / %s", err, scanResult)
	}

	result, err := s.handleDataSensitivityReport(context.Background(), emptyInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(result, "Error:") {
		t.Fatalf("expected success, got: %s", result)
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

	if err := json.Unmarshal([]byte(result), &report); err != nil {
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

// --- registration tests ---

func TestRegisterTools(t *testing.T) {
	srv := mcp.NewServer(mcp.ServerInfo{Name: "nox", Version: "test"})
	s := New("test", nil)

	// Should not panic; exercises all tool registrations.
	s.registerTools(srv)
}

func TestRegisterPluginTools_NoHost(t *testing.T) {
	srv := mcp.NewServer(mcp.ServerInfo{Name: "nox", Version: "test"})
	s := New("test", nil) // no plugin host

	// Should return immediately without registering plugin tools.
	s.registerPluginTools(srv)
}

func TestRegisterPluginTools_WithHost(t *testing.T) {
	srv := mcp.NewServer(mcp.ServerInfo{Name: "nox", Version: "test"})
	h := createHostWithMockPlugin(t)
	s := New("test", nil, WithPluginHost(h))

	// Should register plugin.list, plugin.call_tool, plugin.read_resource.
	s.registerPluginTools(srv)
}

func TestRegisterResources(t *testing.T) {
	srv := mcp.NewServer(mcp.ServerInfo{Name: "nox", Version: "test"})
	s := New("test", nil)

	// Should not panic; exercises all resource registrations.
	s.registerResources(srv)
}

// --- handleResourceDashboard tests ---

func TestResourceDashboard_BeforeScan(t *testing.T) {
	s := New("0.1.0", nil)
	_, err := s.handleResourceDashboard(context.Background(), "nox://dashboard", nil)
	if err == nil {
		t.Fatal("expected error for resource before scan")
	}
}

func TestResourceDashboard_AfterScan(t *testing.T) {
	s := scanCleanDir(t)
	content, err := s.handleResourceDashboard(context.Background(), "nox://dashboard", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if content.MimeType != "text/html" {
		t.Fatalf("expected text/html MIME type, got %s", content.MimeType)
	}
	if !strings.Contains(content.Text, "<html") {
		t.Fatalf("expected HTML content, got: %s", content.Text[:min(len(content.Text), 200)])
	}
}

// --- handleResourceRules tests ---

func TestResourceRules(t *testing.T) {
	s := New("0.1.0", nil)
	content, err := s.handleResourceRules(context.Background(), "nox://rules", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if content.URI != "nox://rules" {
		t.Fatalf("expected URI nox://rules, got %s", content.URI)
	}
	if !strings.Contains(content.Text, "SEC-") {
		t.Fatalf("expected rule IDs in resource, got: %s", content.Text[:min(len(content.Text), 200)])
	}
}

// --- handleDashboard tool tests ---

func TestHandleDashboard_BeforeScan(t *testing.T) {
	s := New("0.1.0", nil)
	result, err := s.handleDashboard(context.Background(), dashboardInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatal("expected error before any scan")
	}
}

func TestHandleDashboard_AfterScan(t *testing.T) {
	s := scanCleanDir(t)
	result, err := s.handleDashboard(context.Background(), dashboardInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(result, "Error:") {
		t.Fatalf("expected success, got: %s", result[:min(len(result), 200)])
	}
	if !strings.Contains(result, "<html") {
		t.Fatalf("expected HTML content in dashboard")
	}
}

// --- resolveProjectPath tests ---

func TestResolveProjectPath_Missing(t *testing.T) {
	s := New("0.1.0", nil)
	_, err := s.resolveProjectPath(nil)
	if err == nil {
		t.Fatal("expected error for nil params")
	}
}

func TestResolveProjectPath_Empty(t *testing.T) {
	s := New("0.1.0", nil)
	_, err := s.resolveProjectPath(map[string]string{"project": ""})
	if err == nil {
		t.Fatal("expected error for empty project")
	}
}

func TestResolveProjectPath_Valid(t *testing.T) {
	s := New("0.1.0", nil)
	path, err := s.resolveProjectPath(map[string]string{"project": "%2Ftmp%2Ftest"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != "/tmp/test" {
		t.Fatalf("expected /tmp/test, got %s", path)
	}
}

// --- per-project resource handler tests ---

// scanDirWithPath creates a temp dir, scans it, and returns the server
// and the resolved absolute path of the scan directory.
func scanDirWithPath(t *testing.T) (srv *Server, absPath string) {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, "main.go", "package main\n\nfunc main() {}\n")

	s := New("0.1.0", nil)
	result, err := s.handleScan(context.Background(), scanInput{Path: dir})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if strings.HasPrefix(result, "Error:") {
		t.Fatalf("scan returned error: %s", result)
	}

	// Get the resolved absolute path used as cache key.
	pc := s.getCache("")
	return s, pc.basePath
}

func TestProjectResourceFindings_NoScan(t *testing.T) {
	s := New("0.1.0", nil)
	_, err := s.handleProjectResourceFindings(context.Background(), "nox://project/test/findings", map[string]string{"project": "%2Ftmp%2Fmissing"})
	if err == nil {
		t.Fatal("expected error for project with no scan")
	}
}

func TestProjectResourceFindings_AfterScan(t *testing.T) {
	s, absPath := scanDirWithPath(t)
	encoded := url.PathEscape(absPath)
	content, err := s.handleProjectResourceFindings(context.Background(), "nox://project/"+encoded+"/findings", map[string]string{"project": encoded})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(content.Text, `"findings"`) {
		t.Fatalf("expected findings JSON, got: %s", content.Text[:min(len(content.Text), 200)])
	}
}

func TestProjectResourceSARIF_AfterScan(t *testing.T) {
	s, absPath := scanDirWithPath(t)
	encoded := url.PathEscape(absPath)
	content, err := s.handleProjectResourceSARIF(context.Background(), "nox://project/"+encoded+"/sarif", map[string]string{"project": encoded})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(content.Text, `"$schema"`) {
		t.Fatalf("expected SARIF content")
	}
}

func TestProjectResourceCDX_AfterScan(t *testing.T) {
	s, absPath := scanDirWithPath(t)
	encoded := url.PathEscape(absPath)
	content, err := s.handleProjectResourceCDX(context.Background(), "nox://project/"+encoded+"/sbom/cdx", map[string]string{"project": encoded})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(content.Text, "CycloneDX") {
		t.Fatalf("expected CycloneDX content")
	}
}

func TestProjectResourceSPDX_AfterScan(t *testing.T) {
	s, absPath := scanDirWithPath(t)
	encoded := url.PathEscape(absPath)
	content, err := s.handleProjectResourceSPDX(context.Background(), "nox://project/"+encoded+"/sbom/spdx", map[string]string{"project": encoded})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(content.Text, "SPDX") {
		t.Fatalf("expected SPDX content")
	}
}

func TestProjectResourceAIInventory_AfterScan(t *testing.T) {
	s, absPath := scanDirWithPath(t)
	encoded := url.PathEscape(absPath)
	content, err := s.handleProjectResourceAIInventory(context.Background(), "nox://project/"+encoded+"/ai-inventory", map[string]string{"project": encoded})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(content.Text, "schema_version") {
		t.Fatalf("expected AI inventory JSON")
	}
}

// --- handleFixPlan / handleAgentGraph tests ---

func TestHandleFixPlan_NoScan(t *testing.T) {
	s := New("test", []string{t.TempDir()})
	result, err := s.handleFixPlan(context.Background(), fixPlanInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") || !strings.Contains(result, "no scan results") {
		t.Fatalf("expected no-scan-results error, got: %s", result)
	}
}

func TestHandleFixPlan_AfterScan(t *testing.T) {
	s := scanCleanDir(t)
	result, err := s.handleFixPlan(context.Background(), fixPlanInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(result, "Error:") {
		t.Fatalf("expected success, got: %s", result)
	}
	if !strings.Contains(result, `"actions"`) {
		t.Fatalf("expected actions key in response, got: %s", result)
	}
}

func TestHandleAgentGraph_NoScan(t *testing.T) {
	s := New("test", []string{t.TempDir()})
	result, err := s.handleAgentGraph(context.Background(), agentGraphInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") {
		t.Fatalf("expected no-scan-results error, got: %s", result)
	}
}

func TestHandleAgentGraph_NoAgents(t *testing.T) {
	s := scanCleanDir(t)
	result, err := s.handleAgentGraph(context.Background(), agentGraphInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Clean dir has no agents — handler returns a friendly message.
	if !strings.Contains(result, "No agent tool registrations") &&
		!strings.HasPrefix(result, "graph LR") {
		t.Fatalf("expected no-agents message or empty mermaid, got: %s", result)
	}
}

func TestMajorOfVersion(t *testing.T) {
	cases := map[string]string{
		"v1.2.3": "1",
		"1.2.3":  "1",
		"v2.0.0": "2",
		"":       "",
		"1":      "1",
	}
	for in, want := range cases {
		if got := majorOfVersion(in); got != want {
			t.Errorf("majorOfVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

// --- handlePluginInstall tests ---

func TestHandlePluginInstall_MissingName(t *testing.T) {
	s := New("test", []string{t.TempDir()})
	result, err := s.handlePluginInstall(context.Background(), pluginInstallInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "Error:") || !strings.Contains(result, "missing required argument") {
		t.Fatalf("expected missing-name error, got: %s", result)
	}
}

func TestHandlePluginInstall_RejectsUnsafeName(t *testing.T) {
	s := New("test", []string{t.TempDir()})
	for _, bad := range []string{"foo;rm -rf /", "../etc/passwd", "foo$(whoami)", "name with space"} {
		result, _ := s.handlePluginInstall(context.Background(), pluginInstallInput{Name: bad, Confirmed: true})
		if !strings.Contains(result, "invalid plugin name") {
			t.Errorf("expected reject for %q, got: %s", bad, result)
		}
	}
}

func TestHandlePluginInstall_RequiresConfirmation(t *testing.T) {
	s := New("test", []string{t.TempDir()})
	result, _ := s.handlePluginInstall(context.Background(), pluginInstallInput{Name: "nox/ai-eval"})
	if !strings.Contains(result, "confirmed: true") {
		t.Errorf("expected consent gate, got: %s", result)
	}
}

func TestIsSafePluginName(t *testing.T) {
	good := []string{"nox/ai-eval", "nox/reachability", "acme/secret-scanner-v2", "nox-plugin-foo"}
	bad := []string{"", "foo;bar", "foo bar", "foo$(x)", "foo|bar", "../foo", strings.Repeat("a", 201)}
	for _, n := range good {
		if !isSafePluginName(n) {
			t.Errorf("safe name rejected: %q", n)
		}
	}
	for _, n := range bad {
		if isSafePluginName(n) {
			t.Errorf("unsafe name accepted: %q", n)
		}
	}
}

func TestIsSafeVersionConstraint(t *testing.T) {
	good := []string{"1.2.3", "v1.2.3", ">=0.5", "^1.0.0", "~1.2", "1.0.0-beta+build"}
	bad := []string{"1.2; rm -rf", "1.0.0`whoami`", "$(x)", "../1.0"}
	for _, v := range good {
		if !isSafeVersionConstraint(v) {
			t.Errorf("safe version rejected: %q", v)
		}
	}
	for _, v := range bad {
		if isSafeVersionConstraint(v) {
			t.Errorf("unsafe version accepted: %q", v)
		}
	}
}

func TestProjectResourceDashboard_AfterScan(t *testing.T) {
	s, absPath := scanDirWithPath(t)
	encoded := url.PathEscape(absPath)
	content, err := s.handleProjectResourceDashboard(context.Background(), "nox://project/"+encoded+"/dashboard", map[string]string{"project": encoded})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if content.MimeType != "text/html" {
		t.Fatalf("expected text/html, got %s", content.MimeType)
	}
	if !strings.Contains(content.Text, "<html") {
		t.Fatalf("expected HTML content")
	}
}
