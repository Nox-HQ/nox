package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
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
	req.Params.URI = "hardline://findings"

	_, err := s.handleResourceFindings(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for resource before scan")
	}
}

func TestResourceFindings_AfterScan(t *testing.T) {
	s := scanCleanDir(t)
	req := mcp.ReadResourceRequest{}
	req.Params.URI = "hardline://findings"

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
	if tc.URI != "hardline://findings" {
		t.Fatalf("expected URI hardline://findings, got %s", tc.URI)
	}
	if !strings.Contains(tc.Text, `"findings"`) {
		t.Fatalf("expected findings JSON, got: %s", tc.Text)
	}
}

func TestResourceSARIF_AfterScan(t *testing.T) {
	s := scanCleanDir(t)
	req := mcp.ReadResourceRequest{}
	req.Params.URI = "hardline://sarif"

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
	req.Params.URI = "hardline://sbom/cdx"

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
	req.Params.URI = "hardline://sbom/spdx"

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
	req.Params.URI = "hardline://ai-inventory"

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
