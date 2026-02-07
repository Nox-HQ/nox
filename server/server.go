// Package server implements the MCP server for agent-safe artifact serving.
package server

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	hardline "github.com/felixgeelhaar/hardline/core"
	"github.com/felixgeelhaar/hardline/core/report"
	"github.com/felixgeelhaar/hardline/core/report/sarif"
	"github.com/felixgeelhaar/hardline/core/report/sbom"
	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

const (
	// maxOutputBytes is the maximum response size before truncation (1 MB).
	maxOutputBytes = 1 << 20
)

// Server is the hardline MCP server.
type Server struct {
	version      string
	allowedPaths []string

	mu    sync.RWMutex
	cache *hardline.ScanResult
}

// New creates a new MCP server. If allowedPaths is empty, any path is allowed.
func New(version string, allowedPaths []string) *Server {
	// Resolve allowed paths to absolute for consistent comparison.
	resolved := make([]string, 0, len(allowedPaths))
	for _, p := range allowedPaths {
		abs, err := filepath.Abs(p)
		if err == nil {
			resolved = append(resolved, abs)
		}
	}
	return &Server{
		version:      version,
		allowedPaths: resolved,
	}
}

// Serve starts the MCP server on stdio and blocks until the client disconnects.
func (s *Server) Serve() error {
	srv := mcpserver.NewMCPServer(
		"hardline",
		s.version,
		mcpserver.WithRecovery(),
		mcpserver.WithToolCapabilities(false),
		mcpserver.WithResourceCapabilities(false, false),
	)

	s.registerTools(srv)
	s.registerResources(srv)

	return mcpserver.ServeStdio(srv)
}

func (s *Server) registerTools(srv *mcpserver.MCPServer) {
	// scan tool — runs the full scan pipeline.
	srv.AddTool(
		mcp.NewTool("scan",
			mcp.WithDescription("Scan a directory for security findings, dependencies, and AI components"),
			mcp.WithString("path",
				mcp.Description("Absolute path to the directory to scan"),
				mcp.Required(),
			),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		s.handleScan,
	)

	// get_findings tool — returns findings from the last scan.
	srv.AddTool(
		mcp.NewTool("get_findings",
			mcp.WithDescription("Get security findings from the last scan"),
			mcp.WithString("format",
				mcp.Description("Output format: json or sarif"),
				mcp.Enum("json", "sarif"),
				mcp.DefaultString("json"),
			),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		s.handleGetFindings,
	)

	// get_sbom tool — returns SBOM from the last scan.
	srv.AddTool(
		mcp.NewTool("get_sbom",
			mcp.WithDescription("Get software bill of materials from the last scan"),
			mcp.WithString("format",
				mcp.Description("Output format: cdx or spdx"),
				mcp.Enum("cdx", "spdx"),
				mcp.DefaultString("cdx"),
			),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		s.handleGetSBOM,
	)
}

func (s *Server) registerResources(srv *mcpserver.MCPServer) {
	srv.AddResource(
		mcp.NewResource("hardline://findings", "Findings JSON",
			mcp.WithResourceDescription("Security findings in hardline JSON format"),
			mcp.WithMIMEType("application/json"),
		),
		s.handleResourceFindings,
	)

	srv.AddResource(
		mcp.NewResource("hardline://sarif", "SARIF Report",
			mcp.WithResourceDescription("Security findings in SARIF 2.1.0 format"),
			mcp.WithMIMEType("application/json"),
		),
		s.handleResourceSARIF,
	)

	srv.AddResource(
		mcp.NewResource("hardline://sbom/cdx", "CycloneDX SBOM",
			mcp.WithResourceDescription("Software bill of materials in CycloneDX format"),
			mcp.WithMIMEType("application/json"),
		),
		s.handleResourceCDX,
	)

	srv.AddResource(
		mcp.NewResource("hardline://sbom/spdx", "SPDX SBOM",
			mcp.WithResourceDescription("Software bill of materials in SPDX format"),
			mcp.WithMIMEType("application/json"),
		),
		s.handleResourceSPDX,
	)

	srv.AddResource(
		mcp.NewResource("hardline://ai-inventory", "AI Inventory",
			mcp.WithResourceDescription("Inventory of AI components discovered during scan"),
			mcp.WithMIMEType("application/json"),
		),
		s.handleResourceAIInventory,
	)
}

// isPathAllowed checks if the given path is under one of the allowed workspace roots.
func (s *Server) isPathAllowed(path string) error {
	if len(s.allowedPaths) == 0 {
		return nil
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("cannot resolve path: %w", err)
	}

	for _, allowed := range s.allowedPaths {
		// Use filepath.Rel to check containment properly.
		rel, err := filepath.Rel(allowed, abs)
		if err != nil {
			continue
		}
		// If the relative path doesn't start with "..", it's under the allowed root.
		if !strings.HasPrefix(rel, "..") {
			return nil
		}
	}

	return fmt.Errorf("path %q is outside allowed workspaces", path)
}

func (s *Server) handleScan(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path, err := request.RequireString("path")
	if err != nil {
		return mcp.NewToolResultError("missing required argument: path"), nil
	}

	if err := s.isPathAllowed(path); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	result, err := hardline.RunScan(path)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("scan failed: %v", err)), nil
	}

	// Cache the result for subsequent tool/resource calls.
	s.mu.Lock()
	s.cache = result
	s.mu.Unlock()

	findingCount := len(result.Findings.Findings())
	pkgCount := len(result.Inventory.Packages())
	aiCount := len(result.AIInventory.Components)

	summary := fmt.Sprintf("Scan complete: %d findings, %d dependencies, %d AI components",
		findingCount, pkgCount, aiCount)

	return mcp.NewToolResultText(summary), nil
}

func (s *Server) handleGetFindings(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.mu.RLock()
	cache := s.cache
	s.mu.RUnlock()

	if cache == nil {
		return mcp.NewToolResultError("no scan results available — run the scan tool first"), nil
	}

	format := request.GetString("format", "json")

	var data []byte
	var err error

	switch format {
	case "sarif":
		r := sarif.NewReporter(s.version, nil)
		data, err = r.Generate(cache.Findings)
	default:
		r := report.NewJSONReporter(s.version)
		data, err = r.Generate(cache.Findings)
	}

	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("report generation failed: %v", err)), nil
	}

	return mcp.NewToolResultText(truncate(string(data))), nil
}

func (s *Server) handleGetSBOM(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.mu.RLock()
	cache := s.cache
	s.mu.RUnlock()

	if cache == nil {
		return mcp.NewToolResultError("no scan results available — run the scan tool first"), nil
	}

	format := request.GetString("format", "cdx")

	var data []byte
	var err error

	switch format {
	case "spdx":
		r := sbom.NewSPDXReporter(s.version)
		data, err = r.Generate(cache.Inventory)
	default:
		r := sbom.NewCycloneDXReporter(s.version)
		data, err = r.Generate(cache.Inventory)
	}

	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("SBOM generation failed: %v", err)), nil
	}

	return mcp.NewToolResultText(truncate(string(data))), nil
}

// Resource handlers.

func (s *Server) handleResourceFindings(_ context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	s.mu.RLock()
	cache := s.cache
	s.mu.RUnlock()

	if cache == nil {
		return nil, fmt.Errorf("no scan results available")
	}

	r := report.NewJSONReporter(s.version)
	data, err := r.Generate(cache.Findings)
	if err != nil {
		return nil, fmt.Errorf("generating findings JSON: %w", err)
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      request.Params.URI,
			MIMEType: "application/json",
			Text:     truncate(string(data)),
		},
	}, nil
}

func (s *Server) handleResourceSARIF(_ context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	s.mu.RLock()
	cache := s.cache
	s.mu.RUnlock()

	if cache == nil {
		return nil, fmt.Errorf("no scan results available")
	}

	r := sarif.NewReporter(s.version, nil)
	data, err := r.Generate(cache.Findings)
	if err != nil {
		return nil, fmt.Errorf("generating SARIF: %w", err)
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      request.Params.URI,
			MIMEType: "application/json",
			Text:     truncate(string(data)),
		},
	}, nil
}

func (s *Server) handleResourceCDX(_ context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	s.mu.RLock()
	cache := s.cache
	s.mu.RUnlock()

	if cache == nil {
		return nil, fmt.Errorf("no scan results available")
	}

	r := sbom.NewCycloneDXReporter(s.version)
	data, err := r.Generate(cache.Inventory)
	if err != nil {
		return nil, fmt.Errorf("generating CycloneDX SBOM: %w", err)
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      request.Params.URI,
			MIMEType: "application/json",
			Text:     truncate(string(data)),
		},
	}, nil
}

func (s *Server) handleResourceSPDX(_ context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	s.mu.RLock()
	cache := s.cache
	s.mu.RUnlock()

	if cache == nil {
		return nil, fmt.Errorf("no scan results available")
	}

	r := sbom.NewSPDXReporter(s.version)
	data, err := r.Generate(cache.Inventory)
	if err != nil {
		return nil, fmt.Errorf("generating SPDX SBOM: %w", err)
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      request.Params.URI,
			MIMEType: "application/json",
			Text:     truncate(string(data)),
		},
	}, nil
}

func (s *Server) handleResourceAIInventory(_ context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	s.mu.RLock()
	cache := s.cache
	s.mu.RUnlock()

	if cache == nil {
		return nil, fmt.Errorf("no scan results available")
	}

	data, err := cache.AIInventory.JSON()
	if err != nil {
		return nil, fmt.Errorf("generating AI inventory JSON: %w", err)
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      request.Params.URI,
			MIMEType: "application/json",
			Text:     truncate(string(data)),
		},
	}, nil
}

// truncate limits output to maxOutputBytes, appending a truncation notice if needed.
func truncate(s string) string {
	if len(s) <= maxOutputBytes {
		return s
	}
	return s[:maxOutputBytes] + "\n... [truncated: output exceeded 1MB limit]"
}
