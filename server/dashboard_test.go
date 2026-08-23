package server

import (
	"context"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/dashboard"
)

func TestGenerateDashboardHTML_CleanScan(t *testing.T) {
	s := scanCleanDir(t)

	pc := s.getCache("")

	html, err := dashboard.GenerateHTML(pc.result, "0.1.0", pc.basePath)
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
	scanResult, err := s.handleScan(context.Background(), scanInput{Path: dir})
	if err != nil || strings.HasPrefix(scanResult, "Error:") {
		t.Fatalf("scan failed: %v / %s", err, scanResult)
	}

	pc := s.getCache("")

	html, err := dashboard.GenerateHTML(pc.result, "0.1.0", pc.basePath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(html, "SEC-") {
		t.Fatal("expected rule ID in dashboard data")
	}
}

func TestHandleResourceDashboard_BeforeScan_Dashboard(t *testing.T) {
	s := New("0.1.0", nil)
	_, err := s.handleResourceDashboard(context.Background(), "nox://dashboard", nil)
	if err == nil {
		t.Fatal("expected error for resource before scan")
	}
}

func TestHandleResourceDashboard_AfterScan_Dashboard(t *testing.T) {
	s := scanCleanDir(t)
	content, err := s.handleResourceDashboard(context.Background(), "nox://dashboard", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if content.URI != "nox://dashboard" {
		t.Fatalf("expected URI nox://dashboard, got %s", content.URI)
	}
	if content.MimeType != "text/html" {
		t.Fatalf("expected text/html MIME type, got %s", content.MimeType)
	}
	if !strings.Contains(content.Text, "<html") {
		t.Fatal("expected HTML content")
	}
}
