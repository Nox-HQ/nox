// Package server implements the MCP server for agent-safe artifact serving.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/annotate"
	"github.com/nox-hq/nox/core/badge"
	"github.com/nox-hq/nox/core/baseline"
	"github.com/nox-hq/nox/core/catalog"
	"github.com/nox-hq/nox/core/compliance"
	"github.com/nox-hq/nox/core/detail"
	"github.com/nox-hq/nox/core/diff"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/git"
	"github.com/nox-hq/nox/core/report"
	"github.com/nox-hq/nox/core/report/sarif"
	"github.com/nox-hq/nox/core/report/sbom"
	"github.com/nox-hq/nox/core/vex"
	"github.com/nox-hq/nox/plugin"
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
			mcp.WithBoolean("include_suppressed",
				mcp.Description("Include suppressed/baselined findings (default: false)"),
			),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		s.handleListFindings,
	)

	// baseline_status tool — returns baseline statistics.
	srv.AddTool(
		mcp.NewTool("baseline_status",
			mcp.WithDescription("Show baseline statistics: total entries, expired count, per-severity breakdown"),
			mcp.WithString("path",
				mcp.Description("Absolute path to the project root"),
				mcp.Required(),
			),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		s.handleBaselineStatus,
	)

	// baseline_add tool — add a finding to the baseline by fingerprint.
	srv.AddTool(
		mcp.NewTool("baseline_add",
			mcp.WithDescription("Add a finding to the baseline by fingerprint"),
			mcp.WithString("path",
				mcp.Description("Absolute path to the project root"),
				mcp.Required(),
			),
			mcp.WithString("fingerprint",
				mcp.Description("Finding fingerprint to baseline"),
				mcp.Required(),
			),
			mcp.WithString("reason",
				mcp.Description("Reason for baselining this finding"),
			),
		),
		s.handleBaselineAdd,
	)

	// diff tool — scan changed files between git refs.
	srv.AddTool(
		mcp.NewTool("diff",
			mcp.WithDescription("Scan only changed files between two git refs and return findings"),
			mcp.WithString("path",
				mcp.Description("Absolute path to the git repository"),
				mcp.Required(),
			),
			mcp.WithString("base",
				mcp.Description("Base git ref for comparison (default: main)"),
				mcp.DefaultString("main"),
			),
			mcp.WithString("head",
				mcp.Description("Head git ref for comparison (default: HEAD)"),
				mcp.DefaultString("HEAD"),
			),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		s.handleDiff,
	)

	// badge tool — generate an SVG badge from cached scan results.
	srv.AddTool(
		mcp.NewTool("badge",
			mcp.WithDescription("Generate a security grade SVG badge from the last scan"),
			mcp.WithString("label",
				mcp.Description("Badge label text (default: nox)"),
				mcp.DefaultString("nox"),
			),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		s.handleBadge,
	)

	// version tool — return nox version info.
	srv.AddTool(
		mcp.NewTool("version",
			mcp.WithDescription("Return nox version, commit, and build date"),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		s.handleVersion,
	)

	// rules tool — list all available rules with metadata.
	srv.AddTool(
		mcp.NewTool("rules",
			mcp.WithDescription("List all security rules with ID, description, severity, CWE, and remediation"),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		s.handleRules,
	)

	// protect_status tool — check pre-commit hook installation status.
	srv.AddTool(
		mcp.NewTool("protect_status",
			mcp.WithDescription("Check whether the nox pre-commit hook is installed in a git repository"),
			mcp.WithString("path",
				mcp.Description("Absolute path to the git repository"),
				mcp.Required(),
			),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		s.handleProtectStatus,
	)

	// annotate tool — build a GitHub PR review payload from cached findings.
	srv.AddTool(
		mcp.NewTool("annotate",
			mcp.WithDescription("Build a GitHub PR review payload from findings for posting via the GitHub API"),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		s.handleAnnotate,
	)

	// vex_status tool — show VEX document summary.
	srv.AddTool(
		mcp.NewTool("vex_status",
			mcp.WithDescription("Load a VEX document and show a summary of vulnerability statuses"),
			mcp.WithString("path",
				mcp.Description("Absolute path to the VEX JSON document"),
				mcp.Required(),
			),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		s.handleVEXStatus,
	)

	// compliance_report tool — generate framework-specific compliance report.
	srv.AddTool(
		mcp.NewTool("compliance_report",
			mcp.WithDescription("Generate a compliance report for a specific framework (CIS, PCI-DSS, SOC2, NIST-800-53, HIPAA, OWASP-Top-10, OWASP-LLM-Top-10, OWASP-Agentic)"),
			mcp.WithString("framework",
				mcp.Description("Compliance framework: CIS, PCI-DSS, SOC2, NIST-800-53, HIPAA, OWASP-Top-10, OWASP-LLM-Top-10, OWASP-Agentic"),
				mcp.Required(),
			),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		s.handleComplianceReport,
	)

	// data_sensitivity_report tool — summarize PII/sensitive data findings.
	srv.AddTool(
		mcp.NewTool("data_sensitivity_report",
			mcp.WithDescription("Summarize PII and sensitive data findings from the scan (DATA-* rules)"),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		s.handleDataSensitivityReport,
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

	srv.AddResource(
		mcp.NewResource("nox://rules", "Security Rules",
			mcp.WithResourceDescription("All available security rules with metadata"),
			mcp.WithMIMEType("application/json"),
		),
		s.handleResourceRules,
	)

	srv.AddResource(
		mcp.NewResource("nox://dashboard", "Security Dashboard",
			mcp.WithResourceDescription("Interactive HTML security dashboard with finding summary, rule breakdown, and dependency overview"),
			mcp.WithMIMEType("text/html"),
		),
		s.handleResourceDashboard,
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
	enriched := detail.Enrich(&f, basePath, store.All(), cat, contextLines)

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
	// Only include suppressed findings if explicitly requested.
	filter.IncludeSuppressed = request.GetBool("include_suppressed", false)

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

// Baseline handlers.

func (s *Server) handleBaselineStatus(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path, err := request.RequireString("path")
	if err != nil {
		return mcp.NewToolResultError("missing required argument: path"), nil
	}

	if err := s.isPathAllowed(path); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	bl, err := baseline.Load(baseline.DefaultPath(path))
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("loading baseline: %v", err)), nil
	}

	type statusResponse struct {
		Total   int            `json:"total"`
		Expired int            `json:"expired"`
		BySev   map[string]int `json:"by_severity"`
		Path    string         `json:"path"`
	}

	bySev := make(map[string]int)
	for _, e := range bl.Entries {
		bySev[string(e.Severity)]++
	}

	resp := statusResponse{
		Total:   bl.Len(),
		Expired: bl.ExpiredCount(),
		BySev:   bySev,
		Path:    baseline.DefaultPath(path),
	}

	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("marshalling response: %v", err)), nil
	}

	return mcp.NewToolResultText(string(data)), nil
}

func (s *Server) handleBaselineAdd(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path, err := request.RequireString("path")
	if err != nil {
		return mcp.NewToolResultError("missing required argument: path"), nil
	}

	if err := s.isPathAllowed(path); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	fingerprint, err := request.RequireString("fingerprint")
	if err != nil {
		return mcp.NewToolResultError("missing required argument: fingerprint"), nil
	}

	reason := request.GetString("reason", "")

	// Find the finding in cached scan results.
	s.mu.RLock()
	cache := s.cache
	s.mu.RUnlock()

	if cache == nil {
		return mcp.NewToolResultError("no scan results available — run the scan tool first"), nil
	}

	var matched *findings.Finding
	items := cache.Findings.Findings()
	for i := range items {
		if items[i].Fingerprint == fingerprint {
			matched = &items[i]
			break
		}
	}

	if matched == nil {
		return mcp.NewToolResultError(fmt.Sprintf("finding with fingerprint %q not found in scan results", fingerprint)), nil
	}

	blPath := baseline.DefaultPath(path)
	bl, err := baseline.Load(blPath)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("loading baseline: %v", err)), nil
	}

	bl.Add(&baseline.Entry{
		Fingerprint: matched.Fingerprint,
		RuleID:      matched.RuleID,
		FilePath:    matched.Location.FilePath,
		Severity:    matched.Severity,
		Reason:      reason,
		CreatedAt:   time.Now().UTC(),
	})

	if err := bl.Save(blPath); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("saving baseline: %v", err)), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("Added finding %s to baseline (%d total entries)", fingerprint[:12], bl.Len())), nil
}

// Diff handler.

func (s *Server) handleDiff(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path, err := request.RequireString("path")
	if err != nil {
		return mcp.NewToolResultError("missing required argument: path"), nil
	}

	if err := s.isPathAllowed(path); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	base := request.GetString("base", "main")
	head := request.GetString("head", "HEAD")

	result, err := diff.Run(path, diff.Options{
		Base: base,
		Head: head,
	})
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("diff failed: %v", err)), nil
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("marshalling diff result: %v", err)), nil
	}

	return mcp.NewToolResultText(truncate(string(data))), nil
}

// Badge handler.

func (s *Server) handleBadge(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.mu.RLock()
	cache := s.cache
	s.mu.RUnlock()

	if cache == nil {
		return mcp.NewToolResultError("no scan results available — run the scan tool first"), nil
	}

	label := request.GetString("label", "nox")
	ff := cache.Findings.ActiveFindings()

	result := badge.GenerateFromFindings(ff, label)

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("marshalling badge result: %v", err)), nil
	}

	return mcp.NewToolResultText(truncate(string(data))), nil
}

// Version handler.

func (s *Server) handleVersion(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	info := map[string]string{
		"version": s.version,
	}

	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("marshalling version: %v", err)), nil
	}

	return mcp.NewToolResultText(string(data)), nil
}

// Rules handler.

func (s *Server) handleRules(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	cat := catalog.Catalog()

	data, err := json.MarshalIndent(cat, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("marshalling rules: %v", err)), nil
	}

	return mcp.NewToolResultText(truncate(string(data))), nil
}

// Protect status handler.

const noxHookMarker = "Installed by nox protect"

func (s *Server) handleProtectStatus(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path, err := request.RequireString("path")
	if err != nil {
		return mcp.NewToolResultError("missing required argument: path"), nil
	}

	if err := s.isPathAllowed(path); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	if !git.IsGitRepo(path) {
		return mcp.NewToolResultError("not a git repository"), nil
	}

	repoRoot, err := git.RepoRoot(path)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("resolving repo root: %v", err)), nil
	}

	hookPath := filepath.Join(repoRoot, ".git", "hooks", "pre-commit")

	type protectStatusResponse struct {
		Installed bool   `json:"installed"`
		HookPath  string `json:"hook_path"`
		Message   string `json:"message"`
	}

	content, err := os.ReadFile(hookPath)
	if err != nil {
		resp := protectStatusResponse{
			Installed: false,
			HookPath:  hookPath,
			Message:   "not installed",
		}
		data, _ := json.MarshalIndent(resp, "", "  ")
		return mcp.NewToolResultText(string(data)), nil
	}

	installed := strings.Contains(string(content), noxHookMarker)
	msg := "not installed (pre-commit hook exists but was not installed by nox)"
	if installed {
		msg = "installed"
	}

	resp := protectStatusResponse{
		Installed: installed,
		HookPath:  hookPath,
		Message:   msg,
	}

	data, _ := json.MarshalIndent(resp, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

// Annotate handler.

func (s *Server) handleAnnotate(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.mu.RLock()
	cache := s.cache
	s.mu.RUnlock()

	if cache == nil {
		return mcp.NewToolResultError("no scan results available — run the scan tool first"), nil
	}

	ff := cache.Findings.ActiveFindings()
	payload := annotate.BuildReviewPayload(ff)
	if payload == nil {
		return mcp.NewToolResultText(`{"message":"no findings to annotate"}`), nil
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("marshalling annotate payload: %v", err)), nil
	}

	return mcp.NewToolResultText(truncate(string(data))), nil
}

// Rules resource handler.

func (s *Server) handleResourceRules(_ context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	cat := catalog.Catalog()

	data, err := json.MarshalIndent(cat, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshalling rules: %w", err)
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      request.Params.URI,
			MIMEType: "application/json",
			Text:     truncate(string(data)),
		},
	}, nil
}

// Dashboard resource handler.

func (s *Server) handleResourceDashboard(_ context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	s.mu.RLock()
	cache := s.cache
	basePath := s.scanBasePath
	s.mu.RUnlock()

	if cache == nil {
		return nil, fmt.Errorf("no scan results available")
	}

	html, err := GenerateDashboardHTML(cache, s.version, basePath)
	if err != nil {
		return nil, fmt.Errorf("generating dashboard: %w", err)
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      request.Params.URI,
			MIMEType: "text/html",
			Text:     html,
		},
	}, nil
}

// VEX status handler.

func (s *Server) handleVEXStatus(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path, err := request.RequireString("path")
	if err != nil {
		return mcp.NewToolResultError("missing required argument: path"), nil
	}

	if err := s.isPathAllowed(path); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	doc, err := vex.LoadVEX(path)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("loading VEX document: %v", err)), nil
	}

	type vexStatusResponse struct {
		Path       string         `json:"path"`
		Statements int            `json:"statements"`
		ByStatus   map[string]int `json:"by_status"`
		Summary    string         `json:"summary"`
	}

	byStatus := make(map[string]int)
	for _, stmt := range doc.Statements {
		byStatus[string(stmt.Status)]++
	}

	resp := vexStatusResponse{
		Path:       path,
		Statements: len(doc.Statements),
		ByStatus:   byStatus,
		Summary:    vex.Summary(doc),
	}

	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("marshalling response: %v", err)), nil
	}

	return mcp.NewToolResultText(string(data)), nil
}

// Compliance report handler.

func (s *Server) handleComplianceReport(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	fw, err := request.RequireString("framework")
	if err != nil {
		return mcp.NewToolResultError("missing required argument: framework"), nil
	}

	s.mu.RLock()
	cache := s.cache
	s.mu.RUnlock()

	if cache == nil {
		return mcp.NewToolResultError("no scan results available — run the scan tool first"), nil
	}

	// Collect triggered rule IDs from active findings.
	triggered := make(map[string]struct{})
	activeItems := cache.Findings.ActiveFindings()
	for i := range activeItems {
		triggered[activeItems[i].RuleID] = struct{}{}
	}
	ruleIDs := make([]string, 0, len(triggered))
	for id := range triggered {
		ruleIDs = append(ruleIDs, id)
	}

	compReport := compliance.GenerateReport(compliance.Framework(fw), ruleIDs)

	data, err := json.MarshalIndent(compReport, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("marshalling report: %v", err)), nil
	}

	return mcp.NewToolResultText(truncate(string(data))), nil
}

// Data sensitivity report handler.

func (s *Server) handleDataSensitivityReport(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.mu.RLock()
	cache := s.cache
	s.mu.RUnlock()

	if cache == nil {
		return mcp.NewToolResultError("no scan results available — run the scan tool first"), nil
	}

	// Filter DATA-* findings from active findings.
	type ruleStats struct {
		RuleID      string   `json:"rule_id"`
		Description string   `json:"description"`
		Count       int      `json:"count"`
		Files       []string `json:"files"`
	}
	type report struct {
		TotalFindings int         `json:"total_findings"`
		Rules         []ruleStats `json:"rules"`
		AffectedFiles []string    `json:"affected_files"`
	}

	ruleMap := make(map[string]*ruleStats)
	allFiles := make(map[string]struct{})
	cat := catalog.Catalog()

	activeFindings := cache.Findings.ActiveFindings()
	for i := range activeFindings {
		f := &activeFindings[i]
		if !strings.HasPrefix(f.RuleID, "DATA-") {
			continue
		}

		rs, ok := ruleMap[f.RuleID]
		if !ok {
			desc := f.RuleID
			if meta, exists := cat[f.RuleID]; exists {
				desc = meta.Description
			}
			rs = &ruleStats{
				RuleID:      f.RuleID,
				Description: desc,
			}
			ruleMap[f.RuleID] = rs
		}
		rs.Count++

		fp := f.Location.FilePath
		allFiles[fp] = struct{}{}

		// Track unique files per rule.
		found := false
		for _, existing := range rs.Files {
			if existing == fp {
				found = true
				break
			}
		}
		if !found {
			rs.Files = append(rs.Files, fp)
		}
	}

	// Build sorted slices for deterministic output.
	rules := make([]ruleStats, 0, len(ruleMap))
	for _, rs := range ruleMap {
		sort.Strings(rs.Files)
		rules = append(rules, *rs)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].RuleID < rules[j].RuleID })

	affectedFiles := make([]string, 0, len(allFiles))
	for fp := range allFiles {
		affectedFiles = append(affectedFiles, fp)
	}
	sort.Strings(affectedFiles)

	total := 0
	for _, rs := range rules {
		total += rs.Count
	}

	rpt := report{
		TotalFindings: total,
		Rules:         rules,
		AffectedFiles: affectedFiles,
	}

	data, err := json.MarshalIndent(rpt, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("marshalling report: %v", err)), nil
	}

	return mcp.NewToolResultText(truncate(string(data))), nil
}

// truncate limits output to maxOutputBytes, appending a truncation notice if needed.
func truncate(s string) string {
	if len(s) <= maxOutputBytes {
		return s
	}
	return s[:maxOutputBytes] + "\n... [truncated: output exceeded 1MB limit]"
}
