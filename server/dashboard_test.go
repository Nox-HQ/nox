package server

import (
	"context"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

func TestGenerateDashboardHTML_CleanScan(t *testing.T) {
	s := scanCleanDir(t)

	s.mu.RLock()
	cache := s.cache
	basePath := s.scanBasePath
	s.mu.RUnlock()

	html, err := GenerateDashboardHTML(cache, "0.1.0", basePath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(html, "<html") {
		t.Fatal("expected valid HTML output")
	}
	if !strings.Contains(html, "nox") {
		t.Fatal("expected 'nox' in dashboard")
	}
	if !strings.Contains(html, "Security Dashboard") {
		t.Fatal("expected 'Security Dashboard' in output")
	}
	// Clean scan should have findings data injected (even if empty array).
	if strings.Contains(html, "__NOX_DATA__") {
		t.Fatal("expected __NOX_DATA__ to be replaced with actual data")
	}
}

func TestGenerateDashboardHTML_WithFindings(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

	s := New("0.1.0", nil)
	scanReq := makeToolRequest(t, "scan", map[string]any{"path": dir})
	scanResult, err := s.handleScan(context.Background(), scanReq)
	if err != nil || scanResult.IsError {
		t.Fatalf("scan failed: %v", err)
	}

	s.mu.RLock()
	cache := s.cache
	basePath := s.scanBasePath
	s.mu.RUnlock()

	html, err := GenerateDashboardHTML(cache, "0.1.0", basePath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(html, "SEC-") {
		t.Fatal("expected rule ID in dashboard data")
	}
}

func TestHandleResourceDashboard_BeforeScan(t *testing.T) {
	s := New("0.1.0", nil)
	req := mcp.ReadResourceRequest{}
	req.Params.URI = "nox://dashboard"

	_, err := s.handleResourceDashboard(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for resource before scan")
	}
}

func TestHandleResourceDashboard_AfterScan(t *testing.T) {
	s := scanCleanDir(t)
	req := mcp.ReadResourceRequest{}
	req.Params.URI = "nox://dashboard"

	contents, err := s.handleResourceDashboard(context.Background(), req)
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
	if tc.URI != "nox://dashboard" {
		t.Fatalf("expected URI nox://dashboard, got %s", tc.URI)
	}
	if tc.MIMEType != "text/html" {
		t.Fatalf("expected text/html MIME type, got %s", tc.MIMEType)
	}
	if !strings.Contains(tc.Text, "<html") {
		t.Fatal("expected HTML content")
	}
}
