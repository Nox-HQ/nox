// Package server implements the MCP server for agent-safe artifact serving.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/catalog"
	"github.com/nox-hq/nox/core/detail"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/report"
	"github.com/nox-hq/nox/core/report/sarif"
	"github.com/nox-hq/nox/core/report/sbom"
	"github.com/nox-hq/nox/plugin"
	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

const (
	// maxOutputBytes is the maximum response size before truncation (1 MB).
	maxOutputBytes = 1 << 20
)

// Server is the nox MCP server.
type Server struct {
	version      string
	allowedPaths []string

	mu           sync.RWMutex
	cache        *nox.ScanResult
	scanBasePath string // base path of last scan for source context

	host    *plugin.Host      // optional plugin host
	aliases map[string]string // tool name aliases
}

// ServerOption is a functional option for configuring a Server.
type ServerOption func(*Server)

// WithPluginHost attaches a plugin Host to the server, enabling
// the plugin.list, plugin.call_tool, and plugin.read_resource tools.
func WithPluginHost(h *plugin.Host) ServerOption {
	return func(s *Server) { s.host = h }
}

// WithAliases sets tool name aliases for the plugin bridge.
// Keys are alias names, values are the real tool names.
func WithAliases(aliases map[string]string) ServerOption {
	return func(s *Server) { s.aliases = aliases }
}

// New creates a new MCP server. If allowedPaths is empty, any path is allowed.
func New(version string, allowedPaths []string, opts ...ServerOption) *Server {
	// Resolve allowed paths to absolute for consistent comparison.
	resolved := make([]string, 0, len(allowedPaths))
	for _, p := range allowedPaths {
		abs, err := filepath.Abs(p)
		if err == nil {
			resolved = append(resolved, abs)
		}
	}
	s := &Server{
		version:      version,
		allowedPaths: resolved,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Serve starts the MCP server on stdio and blocks until the client disconnects.
func (s *Server) Serve() error {
	srv := mcpserver.NewMCPServer(
		"nox",
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

	// get_finding_detail tool — returns enriched detail for a single finding.
	srv.AddTool(
		mcp.NewTool("get_finding_detail",
			mcp.WithDescription("Get detailed information about a finding including source context and remediation"),
			mcp.WithString("finding_id",
				mcp.Description("Finding ID (e.g., SEC-002:config.env:8)"),
				mcp.Required(),
			),
			mcp.WithNumber("context_lines",
				mcp.Description("Number of context lines around the finding"),
			),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		s.handleGetFindingDetail,
	)

	// list_findings tool — returns filtered findings with rule metadata.
	srv.AddTool(
		mcp.NewTool("list_findings",
			mcp.WithDescription("List findings with optional severity, rule, and file filters"),
			mcp.WithString("severity",
				mcp.Description("Comma-separated severities: critical,high,medium,low,info"),
			),
			mcp.WithString("rule",
				mcp.Description("Rule ID pattern (e.g., AI-*, SEC-001)"),
			),
			mcp.WithString("file",
				mcp.Description("File path pattern"),
			),
			mcp.WithNumber("limit",
				mcp.Description("Max findings to return (default: 50)"),
			),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		s.handleListFindings,
	)

	s.registerPluginTools(srv)
}

func (s *Server) registerPluginTools(srv *mcpserver.MCPServer) {
	if s.host == nil {
		return
	}

	srv.AddTool(
		mcp.NewTool("plugin.list",
			mcp.WithDescription("List registered plugins and their capabilities"),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		s.handlePluginList,
	)

	srv.AddTool(
		mcp.NewTool("plugin.call_tool",
			mcp.WithDescription("Invoke a tool provided by a registered plugin"),
			mcp.WithString("tool",
				mcp.Description("Qualified (plugin.tool) or unqualified tool name"),
				mcp.Required(),
			),
			mcp.WithObject("input",
				mcp.Description("Input parameters for the tool"),
			),
			mcp.WithString("workspace_root",
				mcp.Description("Absolute path to the workspace root"),
			),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		s.handlePluginCallTool,
	)

	srv.AddTool(
		mcp.NewTool("plugin.read_resource",
			mcp.WithDescription("Read a resource from a plugin"),
			mcp.WithString("plugin",
				mcp.Description("Plugin name"),
				mcp.Required(),
			),
			mcp.WithString("uri",
				mcp.Description("Resource URI"),
				mcp.Required(),
			),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		s.handlePluginReadResource,
	)
}

func (s *Server) registerResources(srv *mcpserver.MCPServer) {
	srv.AddResource(
		mcp.NewResource("nox://findings", "Findings JSON",
			mcp.WithResourceDescription("Security findings in nox JSON format"),
			mcp.WithMIMEType("application/json"),
		),
		s.handleResourceFindings,
	)

	srv.AddResource(
		mcp.NewResource("nox://sarif", "SARIF Report",
			mcp.WithResourceDescription("Security findings in SARIF 2.1.0 format"),
			mcp.WithMIMEType("application/json"),
		),
		s.handleResourceSARIF,
	)

	srv.AddResource(
		mcp.NewResource("nox://sbom/cdx", "CycloneDX SBOM",
			mcp.WithResourceDescription("Software bill of materials in CycloneDX format"),
			mcp.WithMIMEType("application/json"),
		),
		s.handleResourceCDX,
	)

	srv.AddResource(
		mcp.NewResource("nox://sbom/spdx", "SPDX SBOM",
			mcp.WithResourceDescription("Software bill of materials in SPDX format"),
			mcp.WithMIMEType("application/json"),
		),
		s.handleResourceSPDX,
	)

	srv.AddResource(
		mcp.NewResource("nox://ai-inventory", "AI Inventory",
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

	result, err := nox.RunScan(path)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("scan failed: %v", err)), nil
	}

	// Cache the result for subsequent tool/resource calls.
	s.mu.Lock()
	s.cache = result
	s.scanBasePath = path
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

// Plugin bridge handlers.

func (s *Server) handlePluginList(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if s.host == nil {
		return mcp.NewToolResultError("no plugin host configured"), nil
	}

	data, err := serializePluginList(s.host.Plugins())
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("serializing plugin list: %v", err)), nil
	}

	return mcp.NewToolResultText(truncate(string(data))), nil
}

func (s *Server) handlePluginCallTool(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if s.host == nil {
		return mcp.NewToolResultError("no plugin host configured"), nil
	}

	toolName, err := request.RequireString("tool")
	if err != nil {
		return mcp.NewToolResultError("missing required argument: tool"), nil
	}

	toolName = s.resolveToolName(toolName)

	var input map[string]any
	if raw := request.GetArguments()["input"]; raw != nil {
		if m, ok := raw.(map[string]any); ok {
			input = m
		}
	}

	workspaceRoot := request.GetString("workspace_root", "")
	if workspaceRoot != "" {
		if err := s.isPathAllowed(workspaceRoot); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
	}

	resp, err := s.host.InvokeTool(ctx, toolName, input, workspaceRoot)
	if err != nil {
		if _, ok := err.(plugin.RuntimeViolation); ok {
			return mcp.NewToolResultError(fmt.Sprintf("plugin violation: %v", err)), nil
		}
		return mcp.NewToolResultError(fmt.Sprintf("plugin tool invocation failed: %v", err)), nil
	}

	data, err := serializeInvokeResult(resp)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("serializing plugin response: %v", err)), nil
	}

	return mcp.NewToolResultText(truncate(string(data))), nil
}

func (s *Server) handlePluginReadResource(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return mcp.NewToolResultError("plugin.read_resource is not yet implemented"), nil
}

// resolveToolName resolves tool name aliases.
func (s *Server) resolveToolName(name string) string {
	if s.aliases == nil {
		return name
	}
	if resolved, ok := s.aliases[name]; ok {
		return resolved
	}
	return name
}

// Finding detail handlers.

func (s *Server) handleGetFindingDetail(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.mu.RLock()
	cache := s.cache
	basePath := s.scanBasePath
	s.mu.RUnlock()

	if cache == nil {
		return mcp.NewToolResultError("no scan results available — run the scan tool first"), nil
	}

	findingID, err := request.RequireString("finding_id")
	if err != nil {
		return mcp.NewToolResultError("missing required argument: finding_id"), nil
	}

	contextLines := 5
	if cl, ok := request.GetArguments()["context_lines"].(float64); ok && cl > 0 {
		contextLines = int(cl)
	}

	store := detail.LoadFromSet(cache.Findings, basePath)
	f, ok := store.ByID(findingID)
	if !ok {
		return mcp.NewToolResultError(fmt.Sprintf("finding %q not found", findingID)), nil
	}

	cat := catalog.Catalog()
	enriched := detail.Enrich(f, basePath, store.All(), cat, contextLines)

	data, err := json.MarshalIndent(enriched, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("marshalling detail: %v", err)), nil
	}

	return mcp.NewToolResultText(truncate(string(data))), nil
}

func (s *Server) handleListFindings(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.mu.RLock()
	cache := s.cache
	basePath := s.scanBasePath
	s.mu.RUnlock()

	if cache == nil {
		return mcp.NewToolResultError("no scan results available — run the scan tool first"), nil
	}

	store := detail.LoadFromSet(cache.Findings, basePath)
	cat := catalog.Catalog()

	// Build filter.
	var filter detail.Filter
	if sev := request.GetString("severity", ""); sev != "" {
		for _, s := range strings.Split(sev, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				filter.Severities = append(filter.Severities, findings.Severity(s))
			}
		}
	}
	filter.RulePattern = request.GetString("rule", "")
	filter.FilePattern = request.GetString("file", "")

	filtered := store.Filter(filter)

	// Apply limit.
	limit := 50
	if l, ok := request.GetArguments()["limit"].(float64); ok && l > 0 {
		limit = int(l)
	}
	if len(filtered) > limit {
		filtered = filtered[:limit]
	}

	// Enrich each finding with rule metadata.
	type findingSummary struct {
		findings.Finding
		Rule *catalog.RuleMeta `json:"rule,omitempty"`
	}
	var results []findingSummary
	for _, f := range filtered {
		fs := findingSummary{Finding: f}
		if meta, ok := cat[f.RuleID]; ok {
			fs.Rule = &meta
		}
		results = append(results, fs)
	}

	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("marshalling findings: %v", err)), nil
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
