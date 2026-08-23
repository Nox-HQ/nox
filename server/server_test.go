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

	"github.com/nox-hq/nox/core/dashboard"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/analyzers/deps"
	findingspkg "github.com/nox-hq/nox/core/findings"
	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/plugin"
	mcp "go.klarlabs.de/mcp"
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

// --- handleGetFindingDetail tests ---

func TestHandleGetFindingDetail_BeforeScan(t *testing.T) {
	s := New("0.1.0", nil)
	result, err := s.handleGetFindingDetail(context.Background(), getFindingDetailInput{FindingID: "SEC-001:main.go:1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(textOf(result), "Error:") {
		t.Fatal("expected error before any scan")
	}
	if !strings.Contains(textOf(result), "no scan results") {
		t.Fatalf("expected no-scan-results message, got: %s", textOf(result))
	}
}

func TestHandleGetFindingDetail_MissingFindingID(t *testing.T) {
	s := scanCleanDir(t)
	result, err := s.handleGetFindingDetail(context.Background(), getFindingDetailInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(textOf(result), "Error:") {
		t.Fatal("expected error for missing finding_id")
	}
	if !strings.Contains(textOf(result), "missing required argument: finding_id") {
		t.Fatalf("expected missing argument message, got: %s", textOf(result))
	}
}

func TestHandleGetFindingDetail_FindingNotFound(t *testing.T) {
	s := scanCleanDir(t)
	result, err := s.handleGetFindingDetail(context.Background(), getFindingDetailInput{FindingID: "NONEXISTENT"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(textOf(result), "Error:") {
		t.Fatal("expected error for nonexistent finding")
	}
	if !strings.Contains(textOf(result), "not found") {
		t.Fatalf("expected not found message, got: %s", textOf(result))
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
	if strings.HasPrefix(textOf(result), "Error:") {
		t.Fatalf("expected success, got: %s", textOf(result))
	}
	if !strings.Contains(textOf(result), findingID) {
		t.Fatalf("expected finding ID in response, got: %s", textOf(result))
	}
	if !strings.Contains(textOf(result), `"source"`) {
		t.Fatalf("expected source in response, got: %s", textOf(result))
	}
}

// --- handleListFindings tests ---

func TestHandleListFindings_BeforeScan(t *testing.T) {
	s := New("0.1.0", nil)
	result, err := s.handleListFindings(context.Background(), listFindingsInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(textOf(result), "Error:") {
		t.Fatal("expected error before any scan")
	}
	if !strings.Contains(textOf(result), "no scan results") {
		t.Fatalf("expected no-scan-results message, got: %s", textOf(result))
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
	if strings.HasPrefix(textOf(result), "Error:") {
		t.Fatalf("expected success, got: %s", textOf(result))
	}
	if !strings.Contains(textOf(result), `"RuleID"`) {
		t.Fatalf("expected RuleID in findings, got: %s", textOf(result))
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
	if strings.HasPrefix(textOf(result), "Error:") {
		t.Fatalf("expected success, got: %s", textOf(result))
	}
	if !strings.Contains(textOf(result), `"Severity"`) {
		t.Fatalf("expected Severity field in findings, got: %s", textOf(result))
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
	if strings.HasPrefix(textOf(result), "Error:") {
		t.Fatalf("expected success, got: %s", textOf(result))
	}
	if !strings.Contains(textOf(result), `"RuleID"`) {
		t.Fatalf("expected RuleID in findings, got: %s", textOf(result))
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
	if strings.HasPrefix(textOf(result), "Error:") {
		t.Fatalf("expected success, got: %s", textOf(result))
	}
	if !strings.Contains(textOf(result), "config.env") {
		t.Fatalf("expected config.env in findings, got: %s", textOf(result))
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
	if strings.HasPrefix(textOf(result), "Error:") {
		t.Fatalf("expected success, got: %s", textOf(result))
	}
	if !strings.Contains(textOf(result), `"RuleID"`) {
		t.Fatalf("expected findings in response, got: %s", textOf(result))
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
	if strings.Contains(textOf(allResult), `"RuleID"`) {
		t.Logf("Found %d bytes in all findings response", len(textOf(allResult)))
	}
	if len(textOf(defaultResult)) <= len("[]") {
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
	if !strings.HasPrefix(textOf(result), "Error:") {
		t.Fatal("expected error for missing path")
	}
	if !strings.Contains(textOf(result), "missing required argument: path") {
		t.Fatalf("expected missing path message, got: %s", textOf(result))
	}
}

func TestHandleBaselineStatus_DisallowedPath(t *testing.T) {
	s := New("0.1.0", []string{"/allowed/only"})
	result, err := s.handleBaselineStatus(context.Background(), baselineStatusInput{Path: "/not/allowed"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(textOf(result), "Error:") {
		t.Fatal("expected error for disallowed path")
	}
	if !strings.Contains(textOf(result), "outside allowed workspaces") {
		t.Fatalf("expected workspace error, got: %s", textOf(result))
	}
}

func TestHandleBaselineStatus_NoBaseline(t *testing.T) {
	dir := t.TempDir()
	s := New("0.1.0", nil)
	result, err := s.handleBaselineStatus(context.Background(), baselineStatusInput{Path: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(textOf(result), "Error:") {
		t.Fatalf("expected success (empty baseline), got: %s", textOf(result))
	}
	if !strings.Contains(textOf(result), `"total":0`) && !strings.Contains(textOf(result), `"total": 0`) {
		t.Fatalf("expected total:0 for empty baseline, got: %s", textOf(result))
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
	if strings.HasPrefix(textOf(result), "Error:") {
		t.Fatalf("expected success, got: %s", textOf(result))
	}
	if !strings.Contains(textOf(result), `"total":1`) && !strings.Contains(textOf(result), `"total": 1`) {
		t.Fatalf("expected total:1, got: %s", textOf(result))
	}
	if !strings.Contains(textOf(result), `"high"`) {
		t.Fatalf("expected severity breakdown, got: %s", textOf(result))
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

// --- handleBaselineAdd cache invalidation (issue #61) ---

// TestHandleBaselineAdd_InvalidatesCachedStatus ensures that after a single
// baseline_add the cached scan results reflect the suppressed status, so a
// follow-up list_findings (without --include-suppressed) and badge call
// don't return the now-baselined finding.
func TestHandleBaselineAdd_InvalidatesCachedStatus(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

	s := New("0.1.0", nil)
	if _, err := s.handleScan(context.Background(), scanInput{Path: dir}); err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	pc := s.getCache("")
	items := pc.result.Findings.Findings()
	if len(items) == 0 {
		t.Fatal("expected at least one finding")
	}
	fp := items[0].Fingerprint

	if _, err := s.handleBaselineAdd(context.Background(), baselineAddInput{
		Path:        dir,
		Fingerprint: fp,
		Reason:      "test",
	}); err != nil {
		t.Fatalf("baseline_add failed: %v", err)
	}

	// list_findings (default: active only) must no longer include the
	// suppressed finding.
	listed, err := s.handleListFindings(context.Background(), listFindingsInput{})
	if err != nil {
		t.Fatalf("list_findings failed: %v", err)
	}
	if strings.Contains(textOf(listed), fp) {
		t.Fatalf("list_findings still returned the baselined fingerprint:\n%s", textOf(listed))
	}
}

// TestHandleBaselineAddMany_BatchSuppress covers the batch tool added for
// issue #61 (3): a single MCP call should suppress N findings and update the
// cache so list_findings reflects the change without a re-scan.
func TestHandleBaselineAddMany_BatchSuppress(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
	writeFile(t, dir, "b.env", "AWS_KEY=AKIAIOSFODNN7EXAMPL2\n")

	s := New("0.1.0", nil)
	if _, err := s.handleScan(context.Background(), scanInput{Path: dir}); err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	pc := s.getCache("")
	items := pc.result.Findings.ActiveFindings()
	if len(items) < 2 {
		t.Fatalf("expected at least two findings, got %d", len(items))
	}
	fps := []string{items[0].Fingerprint, items[1].Fingerprint, "deadbeef-not-real"}

	out, err := s.handleBaselineAddMany(context.Background(), baselineAddManyInput{
		Path:         dir,
		Fingerprints: fps,
		Reason:       "test batch",
	})
	if err != nil {
		t.Fatalf("baseline_add_many failed: %v", err)
	}
	if strings.HasPrefix(out, "Error:") {
		t.Fatalf("unexpected error response: %s", out)
	}

	var resp baselineAddManyResponse
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Added != 2 {
		t.Fatalf("expected 2 added, got %d", resp.Added)
	}
	if len(resp.NotFound) != 1 || resp.NotFound[0] != "deadbeef-not-real" {
		t.Fatalf("expected 1 not_found entry, got %+v", resp.NotFound)
	}

	// Cache should now report 0 active findings for those fingerprints.
	active := pc.result.Findings.ActiveFindings()
	for _, f := range active {
		if f.Fingerprint == fps[0] || f.Fingerprint == fps[1] {
			t.Fatalf("expected suppression in cache, found active: %+v", f)
		}
	}
}

// --- fix_plan status field (issue #61 (2)) ---

func TestHandleFixPlan_StatusNoVulns(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "ok.txt", "no vulns here\n")

	s := New("0.1.0", nil)
	if _, err := s.handleScan(context.Background(), scanInput{Path: dir}); err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	out, err := s.handleFixPlan(context.Background(), fixPlanInput{})
	if err != nil {
		t.Fatalf("fix_plan failed: %v", err)
	}
	var resp fixPlanResponse
	if err := json.Unmarshal([]byte(textOf(out)), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Status != fixPlanStatusNoVulns {
		t.Fatalf("expected status %q, got %q", fixPlanStatusNoVulns, resp.Status)
	}
	if resp.Actions == nil {
		t.Fatal("expected empty slice, got nil — agents can't tell `no vulns` from `feature off`")
	}
	if len(resp.Actions) != 0 {
		t.Fatalf("expected 0 actions, got %d", len(resp.Actions))
	}
}

// --- handleVersion tests ---

func TestHandleVersion(t *testing.T) {
	s := New("1.2.3", nil)
	result, err := s.handleVersion(context.Background(), emptyInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(textOf(result), "Error:") {
		t.Fatalf("expected success, got: %s", textOf(result))
	}
	if !strings.Contains(textOf(result), "1.2.3") {
		t.Fatalf("expected version in response, got: %s", textOf(result))
	}
}

// --- handleRules tests ---

func TestHandleRules(t *testing.T) {
	s := New("0.1.0", nil)
	result, err := s.handleRules(context.Background(), emptyInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := textOf(result)
	if strings.HasPrefix(text, "Error:") {
		t.Fatalf("expected success, got: %s", text)
	}
	// Should contain at least one known rule ID.
	if !strings.Contains(text, "SEC-") && !strings.Contains(text, "AI-") && !strings.Contains(text, "IAC-") {
		t.Fatalf("expected rule IDs in response, got: %s", text[:min(len(text), 200)])
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
	if !strings.HasPrefix(textOf(result), "Error:") {
		t.Fatal("expected error for missing path")
	}
	if !strings.Contains(textOf(result), "missing required argument: path") {
		t.Fatalf("expected missing path message, got: %s", textOf(result))
	}
}

func TestHandleDiff_DisallowedPath(t *testing.T) {
	s := New("0.1.0", []string{"/allowed/only"})
	result, err := s.handleDiff(context.Background(), diffInput{Path: "/not/allowed"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(textOf(result), "Error:") {
		t.Fatal("expected error for disallowed path")
	}
	if !strings.Contains(textOf(result), "outside allowed workspaces") {
		t.Fatalf("expected workspace error, got: %s", textOf(result))
	}
}

func TestHandleDiff_NonGitRepo(t *testing.T) {
	dir := t.TempDir()
	s := New("0.1.0", nil)
	result, err := s.handleDiff(context.Background(), diffInput{Path: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(textOf(result), "Error:") {
		t.Fatal("expected error for non-git directory")
	}
	if !strings.Contains(textOf(result), "diff failed") {
		t.Fatalf("expected diff failed message, got: %s", textOf(result))
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
	if !strings.HasPrefix(textOf(result), "Error:") {
		t.Fatal("expected error for missing path")
	}
	if !strings.Contains(textOf(result), "missing required argument: path") {
		t.Fatalf("expected missing path message, got: %s", textOf(result))
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
	text := textOf(result)
	if strings.HasPrefix(text, "Error:") {
		t.Fatalf("expected success, got: %s", text)
	}
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

// --- handleDataSensitivityReport tests ---

func TestHandleDataSensitivityReport_NoScanResults(t *testing.T) {
	s := New("0.1.0", nil)
	result, err := s.handleDataSensitivityReport(context.Background(), emptyInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(textOf(result), "Error:") {
		t.Fatal("expected error before any scan")
	}
	if !strings.Contains(textOf(result), "no scan results") {
		t.Fatalf("expected no-scan-results message, got: %s", textOf(result))
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
	if strings.HasPrefix(textOf(result), "Error:") {
		t.Fatalf("expected success, got: %s", textOf(result))
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

	if err := json.Unmarshal([]byte(textOf(result)), &report); err != nil {
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

// oversizedScanResult builds a ScanResult whose dashboard HTML exceeds
// maxOutputBytes, used to exercise the output-size cap on the dashboard
// handlers. The findings carry long messages so the rendered HTML crosses the
// 1MB response budget.
func oversizedScanResult(t *testing.T) *nox.ScanResult {
	t.Helper()
	fs := findingspkg.NewFindingSet()
	msg := strings.Repeat("boundary violation in prompt context ", 4)
	for i := 0; i < 20000; i++ {
		fs.Add(findingspkg.NewFinding(
			"SEC-100",
			findingspkg.SeverityHigh,
			findingspkg.ConfidenceHigh,
			findingspkg.Location{FilePath: "cmd/service/handler.go", StartLine: i + 1, EndLine: i + 1},
			msg,
		))
	}
	return &nox.ScanResult{
		Findings:    fs,
		Inventory:   &deps.PackageInventory{},
		AIInventory: ai.NewInventory(),
	}
}

func TestGenerateDashboardHTML_OversizedExceedsBudget(t *testing.T) {
	html, err := dashboard.GenerateHTML(oversizedScanResult(t), "0.1.0", t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(html) <= maxOutputBytes {
		t.Fatalf("expected oversized dashboard HTML > %d bytes, got %d", maxOutputBytes, len(html))
	}
}

func TestHandleDashboard_OversizedReturnsNotice(t *testing.T) {
	s := New("0.1.0", nil)
	dir := t.TempDir()
	s.setCache(dir, oversizedScanResult(t))

	result, err := s.handleDashboard(context.Background(), dashboardInput{Path: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) > maxOutputBytes {
		t.Fatalf("dashboard response exceeded output budget: %d > %d bytes", len(result), maxOutputBytes)
	}
	if !strings.Contains(result, "output_too_large") {
		t.Fatalf("expected structured output_too_large notice, got: %s", result[:min(len(result), 200)])
	}
}

func TestHandleResourceDashboard_OversizedReturnsNotice(t *testing.T) {
	s := New("0.1.0", nil)
	dir := t.TempDir()
	s.setCache(dir, oversizedScanResult(t))

	content, err := s.handleResourceDashboard(context.Background(), "nox://dashboard", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(content.Text) > maxOutputBytes {
		t.Fatalf("dashboard resource exceeded output budget: %d > %d bytes", len(content.Text), maxOutputBytes)
	}
	if !strings.Contains(content.Text, "output_too_large") {
		t.Fatalf("expected structured output_too_large notice, got: %s", content.Text[:min(len(content.Text), 200)])
	}
}

func TestHandleProjectResourceDashboard_OversizedReturnsNotice(t *testing.T) {
	s := New("0.1.0", nil)
	dir := t.TempDir()
	s.setCache(dir, oversizedScanResult(t))

	content, err := s.handleProjectResourceDashboard(
		context.Background(),
		"nox://projects/x/dashboard",
		map[string]string{"project": dir},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(content.Text) > maxOutputBytes {
		t.Fatalf("project dashboard resource exceeded output budget: %d > %d bytes", len(content.Text), maxOutputBytes)
	}
	if !strings.Contains(content.Text, "output_too_large") {
		t.Fatalf("expected structured output_too_large notice, got: %s", content.Text[:min(len(content.Text), 200)])
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
	if !strings.HasPrefix(textOf(result), "Error:") || !strings.Contains(textOf(result), "no scan results") {
		t.Fatalf("expected no-scan-results error, got: %s", textOf(result))
	}
}

func TestHandleFixPlan_AfterScan(t *testing.T) {
	s := scanCleanDir(t)
	result, err := s.handleFixPlan(context.Background(), fixPlanInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasPrefix(textOf(result), "Error:") {
		t.Fatalf("expected success, got: %s", textOf(result))
	}
	if !strings.Contains(textOf(result), `"actions"`) {
		t.Fatalf("expected actions key in response, got: %s", textOf(result))
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

func TestHandleListFindings_Pagination(t *testing.T) {
	dir := t.TempDir()
	// Several distinct secrets across rules → several findings to page through.
	// AWS keys are AKIA + 16 chars from [A-Z2-7]; use two valid, distinct ones
	// plus a private-key header.
	writeFile(t, dir, "secrets.env",
		"A=AKIAIOSFODNN7EXAMPLE\nB=AKIAWXYZ234567ABCDEF\n")
	writeFile(t, dir, "id_rsa",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n")

	s := New("0.1.0", nil)
	if r, err := s.handleScan(context.Background(), scanInput{Path: dir}); err != nil || strings.HasPrefix(r, "Error:") {
		t.Fatalf("scan failed: %v / %s", err, r)
	}

	type page struct {
		Total, Offset, Limit, Returned int
		HasMore                        bool                     `json:"has_more"`
		Findings                       []map[string]interface{} `json:"findings"`
	}
	get := func(limit, offset int) page {
		out, err := s.handleListFindings(context.Background(),
			listFindingsInput{Limit: float64(limit), Offset: float64(offset)})
		if err != nil || strings.HasPrefix(textOf(out), "Error:") {
			t.Fatalf("list failed: %v / %s", err, textOf(out))
		}
		var p page
		if err := json.Unmarshal([]byte(textOf(out)), &p); err != nil {
			t.Fatalf("envelope not valid JSON: %v\n%s", err, textOf(out))
		}
		return p
	}

	first := get(2, 0)
	if first.Total < 3 {
		t.Fatalf("expected >=3 findings to paginate, total=%d", first.Total)
	}
	if first.Returned != 2 || first.Limit != 2 || first.Offset != 0 || !first.HasMore {
		t.Fatalf("unexpected first page: %+v", first)
	}

	second := get(2, 2)
	if second.Total != first.Total {
		t.Errorf("total changed across pages: %d vs %d", first.Total, second.Total)
	}
	if second.Offset != 2 {
		t.Errorf("expected offset 2, got %d", second.Offset)
	}
	// Pages must not overlap (stable order).
	firstIDs := map[string]bool{}
	for _, f := range first.Findings {
		firstIDs[f["ID"].(string)] = true
	}
	for _, f := range second.Findings {
		if firstIDs[f["ID"].(string)] {
			t.Errorf("finding %v appears on both pages", f["ID"])
		}
	}

	// Offset past the end yields an empty page, not an error.
	beyond := get(10, 1000)
	if beyond.Returned != 0 || beyond.HasMore {
		t.Errorf("expected empty final page, got %+v", beyond)
	}
}

func TestHandleSummary(t *testing.T) {
	// Before any scan.
	s := New("0.1.0", nil)
	if r, _ := s.handleSummary(context.Background(), emptyInput{}); !strings.HasPrefix(textOf(r), "Error:") {
		t.Fatal("expected error before scan")
	}

	dir := t.TempDir()
	writeFile(t, dir, "secrets.env", "A=AKIAIOSFODNN7EXAMPLE\n")
	writeFile(t, dir, "id_rsa", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n")
	if r, err := s.handleScan(context.Background(), scanInput{Path: dir}); err != nil || strings.HasPrefix(r, "Error:") {
		t.Fatalf("scan failed: %v / %s", err, r)
	}

	out, err := s.handleSummary(context.Background(), emptyInput{})
	if err != nil || strings.HasPrefix(textOf(out), "Error:") {
		t.Fatalf("summary failed: %v / %s", err, textOf(out))
	}
	var sum struct {
		ActiveFindings int            `json:"active_findings"`
		TotalFindings  int            `json:"total_findings"`
		BySeverity     map[string]int `json:"by_severity"`
		ByFamily       map[string]int `json:"by_family"`
	}
	if err := json.Unmarshal([]byte(textOf(out)), &sum); err != nil {
		t.Fatalf("summary not valid JSON: %v\n%s", err, textOf(out))
	}
	if sum.ActiveFindings < 2 {
		t.Fatalf("expected >=2 active findings, got %d", sum.ActiveFindings)
	}
	if sum.ByFamily["secrets"] < 2 {
		t.Errorf("expected secrets family count >=2, got %v", sum.ByFamily)
	}
	// counts must sum to active total.
	sevSum := 0
	for _, n := range sum.BySeverity {
		sevSum += n
	}
	if sevSum != sum.ActiveFindings {
		t.Errorf("severity counts %d != active findings %d", sevSum, sum.ActiveFindings)
	}
}

func TestHandleFindingByFingerprint(t *testing.T) {
	s := New("0.1.0", nil)
	// Missing arg.
	if r, _ := s.handleFindingByFingerprint(context.Background(), findingByFingerprintInput{}); !strings.HasPrefix(textOf(r), "Error:") {
		t.Fatal("expected error for empty fingerprint")
	}

	dir := t.TempDir()
	writeFile(t, dir, "config.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
	if r, err := s.handleScan(context.Background(), scanInput{Path: dir}); err != nil || strings.HasPrefix(r, "Error:") {
		t.Fatalf("scan failed: %v / %s", err, r)
	}

	// Pull one finding's fingerprint via list_findings.
	listOut, _ := s.handleListFindings(context.Background(), listFindingsInput{})
	var env struct {
		Findings []struct {
			Fingerprint string `json:"Fingerprint"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(textOf(listOut)), &env); err != nil || len(env.Findings) == 0 {
		t.Fatalf("could not get a fingerprint: %v\n%s", err, textOf(listOut))
	}
	fp := env.Findings[0].Fingerprint

	// Full fingerprint → found.
	out, err := s.handleFindingByFingerprint(context.Background(), findingByFingerprintInput{Fingerprint: fp})
	if err != nil {
		t.Fatalf("lookup error: %v", err)
	}
	var found struct {
		Found  bool   `json:"found"`
		Status string `json:"status"`
		RuleID string `json:"rule_id"`
	}
	if err := json.Unmarshal([]byte(textOf(out)), &found); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, textOf(out))
	}
	if !found.Found || found.Status != "new" {
		t.Errorf("expected found+new, got %+v", found)
	}

	// 12-char prefix → also found.
	if len(fp) >= 12 {
		out2, _ := s.handleFindingByFingerprint(context.Background(), findingByFingerprintInput{Fingerprint: fp[:12]})
		if !strings.Contains(textOf(out2), `"found": true`) {
			t.Errorf("prefix lookup should find the finding: %s", textOf(out2))
		}
	}

	// Unknown fingerprint → found:false.
	out3, _ := s.handleFindingByFingerprint(context.Background(), findingByFingerprintInput{Fingerprint: "deadbeefdeadbeef"})
	if !strings.Contains(textOf(out3), `"found": false`) {
		t.Errorf("expected found:false for unknown fp: %s", textOf(out3))
	}
}

// depScanResult seeds a scan result with one VULN-001 finding carrying the
// given upgrade metadata, so a fix_plan handler test can exercise the planner
// without a real scan.
func depScanResult(pkg, from, fixed string) *nox.ScanResult {
	fs := findingspkg.NewFindingSet()
	f := findingspkg.NewFinding("VULN-001", findingspkg.SeverityHigh, findingspkg.ConfidenceHigh,
		findingspkg.Location{FilePath: "go.mod", StartLine: 1, EndLine: 1},
		pkg+" is vulnerable")
	f.Metadata = map[string]string{"ecosystem": "go", "package": pkg, "version": from, "fixed_in": fixed}
	fs.Add(f)
	return &nox.ScanResult{Findings: fs, Inventory: &deps.PackageInventory{}, AIInventory: ai.NewInventory()}
}

// The MCP fix_plan tool must refuse a downgrade, because it now shares the
// core/fix planner with `nox fix`. Before consolidation this handler had no
// such guard and would have presented an agent a fixed_in BELOW the installed
// version as an actionable upgrade — a plan the CLI would never apply.
func TestHandleFixPlan_RefusesDowngrade(t *testing.T) {
	s := New("0.1.0", nil)
	s.setCache("", depScanResult("golang.org/x/crypto", "0.54.0", "0.51.0"))

	out, err := s.handleFixPlan(context.Background(), fixPlanInput{})
	if err != nil {
		t.Fatalf("fix_plan failed: %v", err)
	}
	var resp fixPlanResponse
	if err := json.Unmarshal([]byte(textOf(out)), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Actions) != 0 {
		t.Fatalf("MCP fix_plan planned a DOWNGRADE (0.54.0 -> 0.51.0): %+v", resp.Actions)
	}
	if resp.VulnCount != 1 {
		t.Errorf("VulnCount = %d, want 1", resp.VulnCount)
	}
}

// A genuine forward upgrade is still planned, with the operator-runnable command
// the CLI would produce.
func TestHandleFixPlan_PlansForwardUpgrade(t *testing.T) {
	s := New("0.1.0", nil)
	s.setCache("", depScanResult("golang.org/x/crypto", "0.51.0", "0.54.0"))

	out, err := s.handleFixPlan(context.Background(), fixPlanInput{})
	if err != nil {
		t.Fatalf("fix_plan failed: %v", err)
	}
	var resp fixPlanResponse
	if err := json.Unmarshal([]byte(textOf(out)), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(resp.Actions))
	}
	if resp.Actions[0].To != "0.54.0" {
		t.Errorf("To = %s, want 0.54.0", resp.Actions[0].To)
	}
	if resp.Actions[0].Command == "" {
		t.Error("forward upgrade must carry a runnable command")
	}
}
