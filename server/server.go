// Package server implements the MCP server for agent-safe artifact serving.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os/exec"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	mcp "github.com/felixgeelhaar/mcp-go"
	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/annotate"
	"github.com/nox-hq/nox/core/badge"
	"github.com/nox-hq/nox/core/baseline"
	"github.com/nox-hq/nox/core/catalog"
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

// --- Input structs for typed tool handlers ---

type scanInput struct {
	Path string `json:"path"`
}
type getFindingsInput struct {
	Format string `json:"format,omitempty"`
}
type getSBOMInput struct {
	Format string `json:"format,omitempty"`
}
type getFindingDetailInput struct {
	FindingID    string  `json:"finding_id"`
	ContextLines float64 `json:"context_lines,omitempty"`
}
type listFindingsInput struct {
	Severity          string  `json:"severity,omitempty"`
	Rule              string  `json:"rule,omitempty"`
	File              string  `json:"file,omitempty"`
	Limit             float64 `json:"limit,omitempty"`
	IncludeSuppressed bool    `json:"include_suppressed,omitempty"`
}
type baselineStatusInput struct {
	Path string `json:"path"`
}
type baselineAddInput struct {
	Path        string `json:"path"`
	Fingerprint string `json:"fingerprint"`
	Reason      string `json:"reason,omitempty"`
}
type diffInput struct {
	Path string `json:"path"`
	Base string `json:"base,omitempty"`
	Head string `json:"head,omitempty"`
}
type badgeInput struct {
	Label string `json:"label,omitempty"`
}
type emptyInput struct{}
type protectStatusInput struct {
	Path string `json:"path"`
}
type vexStatusInput struct {
	Path string `json:"path"`
}
type dashboardInput struct {
	Path string `json:"path,omitempty"`
}
type pluginCallToolInput struct {
	Tool          string         `json:"tool"`
	Input         map[string]any `json:"input,omitempty"`
	WorkspaceRoot string         `json:"workspace_root,omitempty"`
}
type fixPlanInput struct {
	IncludeMajor bool   `json:"include_major,omitempty"`
	Path         string `json:"path,omitempty"`
}
type agentGraphInput struct {
	Format string `json:"format,omitempty"` // "mermaid" or "dot"; defaults to "mermaid"
}
type pluginInstallInput struct {
	Name       string `json:"name"`               // required: nox/foo or nox-plugin-foo
	Version    string `json:"version,omitempty"`  // optional version constraint
	NeedsConfirm bool `json:"_needs_confirm,omitempty"` // host-set: operator approved active call
}
type pluginReadResourceInput struct {
	Plugin string `json:"plugin"`
	URI    string `json:"uri"`
}

// --- Multi-project cache ---

type projectCache struct {
	result   *nox.ScanResult
	basePath string
}

// Server is the nox MCP server.
type Server struct {
	version      string
	allowedPaths []string

	mu       sync.RWMutex
	projects map[string]*projectCache // key: absolute path
	lastPath string                   // most recently scanned project

	host    *plugin.Host      // optional plugin host
	aliases map[string]string // tool name aliases
}

// Option is a functional option for configuring a Server.
type Option func(*Server)

// WithPluginHost attaches a plugin Host to the server, enabling
// the plugin.list, plugin.call_tool, and plugin.read_resource tools.
func WithPluginHost(h *plugin.Host) Option {
	return func(s *Server) { s.host = h }
}

// WithAliases sets tool name aliases for the plugin bridge.
// Keys are alias names, values are the real tool names.
func WithAliases(aliases map[string]string) Option {
	return func(s *Server) { s.aliases = aliases }
}

// New creates a new MCP server. If allowedPaths is empty, any path is allowed.
func New(version string, allowedPaths []string, opts ...Option) *Server {
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
		projects:     make(map[string]*projectCache),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// getCache returns the project cache for the given path.
// If path is empty, returns the most recently scanned project's cache.
func (s *Server) getCache(path string) *projectCache {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if path == "" {
		path = s.lastPath
	}
	if path == "" {
		return nil
	}
	return s.projects[path]
}

// setCache stores a scan result under the given project path.
func (s *Server) setCache(path string, result *nox.ScanResult) {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.projects[abs] = &projectCache{
		result:   result,
		basePath: abs,
	}
	s.lastPath = abs
}

// Serve starts the MCP server on stdio and blocks until the client disconnects.
func (s *Server) Serve() error {
	srv := mcp.NewServer(mcp.ServerInfo{
		Name:    "nox",
		Version: s.version,
	})

	s.registerTools(srv)
	s.registerResources(srv)

	return mcp.ServeStdio(context.Background(), srv)
}

func (s *Server) registerTools(srv *mcp.Server) {
	srv.Tool("scan").
		Description("Scan a directory for security findings, dependencies, and AI components").
		ReadOnly().
		Handler(s.handleScan)

	srv.Tool("get_findings").
		Description("Get security findings from the last scan").
		ReadOnly().
		Handler(s.handleGetFindings)

	srv.Tool("get_sbom").
		Description("Get software bill of materials from the last scan").
		ReadOnly().
		Handler(s.handleGetSBOM)

	srv.Tool("get_finding_detail").
		Description("Get detailed information about a finding including source context and remediation").
		ReadOnly().
		Handler(s.handleGetFindingDetail)

	srv.Tool("list_findings").
		Description("List findings with optional severity, rule, and file filters").
		ReadOnly().
		Handler(s.handleListFindings)

	srv.Tool("baseline_status").
		Description("Show baseline statistics: total entries, expired count, per-severity breakdown").
		ReadOnly().
		Handler(s.handleBaselineStatus)

	srv.Tool("baseline_add").
		Description("Add a finding to the baseline by fingerprint").
		Handler(s.handleBaselineAdd)

	srv.Tool("diff").
		Description("Scan only changed files between two git refs and return findings").
		ReadOnly().
		Handler(s.handleDiff)

	srv.Tool("badge").
		Description("Generate a security grade SVG badge from the last scan").
		ReadOnly().
		Handler(s.handleBadge)

	srv.Tool("version").
		Description("Return nox version, commit, and build date").
		ReadOnly().
		Handler(s.handleVersion)

	srv.Tool("rules").
		Description("List all security rules with ID, description, severity, CWE, and remediation").
		ReadOnly().
		Handler(s.handleRules)

	srv.Tool("protect_status").
		Description("Check whether the nox pre-commit hook is installed in a git repository").
		ReadOnly().
		Handler(s.handleProtectStatus)

	srv.Tool("annotate").
		Description("Build a GitHub PR review payload from findings for posting via the GitHub API").
		ReadOnly().
		Handler(s.handleAnnotate)

	srv.Tool("vex_status").
		Description("Load a VEX document and show a summary of vulnerability statuses").
		ReadOnly().
		Handler(s.handleVEXStatus)

	srv.Tool("fix_plan").
		Description("Plan dependency upgrade actions from VULN-001 findings with fixed_in metadata. Read-only — returns the upgrade plan as a list; never mutates the workspace. Operators apply via the nox fix CLI subcommand.").
		ReadOnly().
		Handler(s.handleFixPlan)

	srv.Tool("agent_graph").
		Description("Render the detected agent capability lattice as Mermaid (default) or Graphviz dot. Drop into a markdown file or render with dot to audit which tools each agent can call.").
		ReadOnly().
		Handler(s.handleAgentGraph)

	srv.Tool("plugin_install").
		Description("Install a nox plugin by name (e.g. nox/ai-eval). Resolves the plugin against configured registries, fetches the platform binary, verifies the digest, and registers it in local state. Network call; not read-only.").
		Handler(s.handlePluginInstall)

	srv.Tool("data_sensitivity_report").
		Description("Summarize PII and sensitive data findings from the scan (DATA-* rules)").
		ReadOnly().
		Handler(s.handleDataSensitivityReport)

	srv.Tool("dashboard").
		Description("Generate an interactive HTML security dashboard from scan results").
		ReadOnly().
		Handler(s.handleDashboard)

	s.registerPluginTools(srv)
}

func (s *Server) registerPluginTools(srv *mcp.Server) {
	if s.host == nil {
		return
	}

	srv.Tool("plugin.list").
		Description("List registered plugins and their capabilities").
		ReadOnly().
		Handler(s.handlePluginList)

	srv.Tool("plugin.call_tool").
		Description("Invoke a tool provided by a registered plugin").
		ReadOnly().
		Handler(s.handlePluginCallTool)

	srv.Tool("plugin.read_resource").
		Description("Read a resource from a plugin").
		ReadOnly().
		Handler(s.handlePluginReadResource)
}

func (s *Server) registerResources(srv *mcp.Server) {
	// Static resources (use last scan)
	srv.Resource("nox://findings").
		Name("Findings JSON").
		Description("Security findings in nox JSON format").
		MimeType("application/json").
		Handler(s.handleResourceFindings)

	srv.Resource("nox://sarif").
		Name("SARIF Report").
		Description("Security findings in SARIF 2.1.0 format").
		MimeType("application/json").
		Handler(s.handleResourceSARIF)

	srv.Resource("nox://sbom/cdx").
		Name("CycloneDX SBOM").
		Description("Software bill of materials in CycloneDX format").
		MimeType("application/json").
		Handler(s.handleResourceCDX)

	srv.Resource("nox://sbom/spdx").
		Name("SPDX SBOM").
		Description("Software bill of materials in SPDX format").
		MimeType("application/json").
		Handler(s.handleResourceSPDX)

	srv.Resource("nox://ai-inventory").
		Name("AI Inventory").
		Description("Inventory of AI components discovered during scan").
		MimeType("application/json").
		Handler(s.handleResourceAIInventory)

	srv.Resource("nox://rules").
		Name("Security Rules").
		Description("All available security rules with metadata").
		MimeType("application/json").
		Handler(s.handleResourceRules)

	srv.Resource("nox://dashboard").
		Name("Security Dashboard").
		Description("Interactive HTML security dashboard with finding summary, rule breakdown, and dependency overview").
		MimeType("text/html").
		Handler(s.handleResourceDashboard)

	// Templated resources (per-project, URL-encoded path)
	srv.Resource("nox://project/{project}/findings").
		Name("Project Findings").
		Description("Security findings for a specific project (project = URL-encoded abs path)").
		MimeType("application/json").
		Handler(s.handleProjectResourceFindings)

	srv.Resource("nox://project/{project}/sarif").
		Name("Project SARIF Report").
		Description("SARIF report for a specific project").
		MimeType("application/json").
		Handler(s.handleProjectResourceSARIF)

	srv.Resource("nox://project/{project}/sbom/cdx").
		Name("Project CycloneDX SBOM").
		Description("CycloneDX SBOM for a specific project").
		MimeType("application/json").
		Handler(s.handleProjectResourceCDX)

	srv.Resource("nox://project/{project}/sbom/spdx").
		Name("Project SPDX SBOM").
		Description("SPDX SBOM for a specific project").
		MimeType("application/json").
		Handler(s.handleProjectResourceSPDX)

	srv.Resource("nox://project/{project}/ai-inventory").
		Name("Project AI Inventory").
		Description("AI inventory for a specific project").
		MimeType("application/json").
		Handler(s.handleProjectResourceAIInventory) // nox:ignore SEC-659 -- function name, not a key

	srv.Resource("nox://project/{project}/dashboard").
		Name("Project Dashboard").
		Description("HTML dashboard for a specific project").
		MimeType("text/html").
		Handler(s.handleProjectResourceDashboard)
}

// isPathAllowed checks if the given path is under one of the allowed workspace roots.
// Symlinks are resolved to prevent symlink-based traversal out of allowed directories.
func (s *Server) isPathAllowed(path string) error {
	if len(s.allowedPaths) == 0 {
		return nil
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("cannot resolve path: %w", err)
	}

	// Resolve symlinks to prevent traversal via symlinks pointing outside
	// the allowed workspace. Fall back to the absolute path if the target
	// does not exist yet (EvalSymlinks requires the path to exist).
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	} else {
		// Path may not exist yet; resolve the parent directory to handle
		// symlinks in ancestor components (e.g., /var → /private/var on macOS).
		parent := filepath.Dir(abs)
		if resolvedParent, err := filepath.EvalSymlinks(parent); err == nil {
			abs = filepath.Join(resolvedParent, filepath.Base(abs))
		}
	}

	for _, allowed := range s.allowedPaths {
		// Resolve symlinks in the allowed root as well.
		allowedResolved := allowed
		if resolved, err := filepath.EvalSymlinks(allowed); err == nil {
			allowedResolved = resolved
		}

		// Use filepath.Rel to check containment properly.
		rel, err := filepath.Rel(allowedResolved, abs)
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

// --- Tool handlers ---

func (s *Server) handleScan(_ context.Context, input scanInput) (string, error) {
	if input.Path == "" {
		return "Error: missing required argument: path", nil
	}

	if err := s.isPathAllowed(input.Path); err != nil {
		return "Error: " + err.Error(), nil
	}

	result, err := nox.RunScan(input.Path)
	if err != nil {
		return "Error: scan failed: " + err.Error(), nil
	}

	s.setCache(input.Path, result)

	findingCount := len(result.Findings.Findings())
	pkgCount := len(result.Inventory.Packages())
	aiCount := len(result.AIInventory.Components)

	return fmt.Sprintf("Scan complete: %d findings, %d dependencies, %d AI components",
		findingCount, pkgCount, aiCount), nil
}

func (s *Server) handleGetFindings(_ context.Context, input getFindingsInput) (string, error) {
	pc := s.getCache("")
	if pc == nil {
		return "Error: no scan results available — run the scan tool first", nil
	}

	format := input.Format
	if format == "" {
		format = "json"
	}

	var data []byte
	var err error

	switch format {
	case "sarif":
		r := sarif.NewReporter(s.version, nil)
		data, err = r.Generate(pc.result.Findings)
	default:
		r := report.NewJSONReporter(s.version)
		data, err = r.Generate(pc.result.Findings)
	}

	if err != nil {
		return "Error: report generation failed: " + err.Error(), nil
	}

	return truncate(string(data)), nil
}

func (s *Server) handleGetSBOM(_ context.Context, input getSBOMInput) (string, error) {
	pc := s.getCache("")
	if pc == nil {
		return "Error: no scan results available — run the scan tool first", nil
	}

	format := input.Format
	if format == "" {
		format = "cdx"
	}

	var data []byte
	var err error

	switch format {
	case "spdx":
		r := sbom.NewSPDXReporter(s.version)
		data, err = r.Generate(pc.result.Inventory)
	default:
		r := sbom.NewCycloneDXReporter(s.version)
		data, err = r.Generate(pc.result.Inventory)
	}

	if err != nil {
		return "Error: SBOM generation failed: " + err.Error(), nil
	}

	return truncate(string(data)), nil
}

func (s *Server) handleGetFindingDetail(_ context.Context, input getFindingDetailInput) (string, error) {
	pc := s.getCache("")
	if pc == nil {
		return "Error: no scan results available — run the scan tool first", nil
	}

	if input.FindingID == "" {
		return "Error: missing required argument: finding_id", nil
	}

	contextLines := 5
	if input.ContextLines > 0 {
		contextLines = int(input.ContextLines)
	}

	store := detail.LoadFromSet(pc.result.Findings, pc.basePath)
	f, ok := store.ByID(input.FindingID)
	if !ok {
		return fmt.Sprintf("Error: finding %q not found", input.FindingID), nil
	}

	cat := catalog.Catalog()
	enriched := detail.Enrich(&f, pc.basePath, store.All(), cat, contextLines)

	data, err := json.MarshalIndent(enriched, "", "  ")
	if err != nil {
		return "Error: marshalling detail: " + err.Error(), nil
	}

	return truncate(string(data)), nil
}

func (s *Server) handleListFindings(_ context.Context, input listFindingsInput) (string, error) {
	pc := s.getCache("")
	if pc == nil {
		return "Error: no scan results available — run the scan tool first", nil
	}

	store := detail.LoadFromSet(pc.result.Findings, pc.basePath)
	cat := catalog.Catalog()

	// Build filter.
	var filter detail.Filter
	if input.Severity != "" {
		for _, sv := range strings.Split(input.Severity, ",") {
			sv = strings.TrimSpace(sv)
			if sv != "" {
				filter.Severities = append(filter.Severities, findings.Severity(sv))
			}
		}
	}
	filter.RulePattern = input.Rule
	filter.FilePattern = input.File
	filter.IncludeSuppressed = input.IncludeSuppressed

	filtered := store.Filter(filter)

	// Apply limit.
	limit := 50
	if input.Limit > 0 {
		limit = int(input.Limit)
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
	for i := range filtered {
		f := &filtered[i]
		fs := findingSummary{Finding: *f}
		if meta, ok := cat[f.RuleID]; ok {
			fs.Rule = &meta
		}
		results = append(results, fs)
	}

	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return "Error: marshalling findings: " + err.Error(), nil
	}

	return truncate(string(data)), nil
}

// Baseline handlers.

func (s *Server) handleBaselineStatus(_ context.Context, input baselineStatusInput) (string, error) {
	if input.Path == "" {
		return "Error: missing required argument: path", nil
	}

	if err := s.isPathAllowed(input.Path); err != nil {
		return "Error: " + err.Error(), nil
	}

	bl, err := baseline.Load(baseline.DefaultPath(input.Path))
	if err != nil {
		return "Error: loading baseline: " + err.Error(), nil
	}

	type statusResponse struct {
		Total   int            `json:"total"`
		Expired int            `json:"expired"`
		BySev   map[string]int `json:"by_severity"`
		Path    string         `json:"path"`
	}

	bySev := make(map[string]int)
	for i := range bl.Entries {
		bySev[string(bl.Entries[i].Severity)]++
	}

	resp := statusResponse{
		Total:   bl.Len(),
		Expired: bl.ExpiredCount(),
		BySev:   bySev,
		Path:    baseline.DefaultPath(input.Path),
	}

	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return "Error: marshalling response: " + err.Error(), nil
	}

	return string(data), nil
}

func (s *Server) handleBaselineAdd(_ context.Context, input baselineAddInput) (string, error) {
	if input.Path == "" {
		return "Error: missing required argument: path", nil
	}

	if err := s.isPathAllowed(input.Path); err != nil {
		return "Error: " + err.Error(), nil
	}

	if input.Fingerprint == "" {
		return "Error: missing required argument: fingerprint", nil
	}

	// Find the finding in cached scan results.
	pc := s.getCache("")
	if pc == nil {
		return "Error: no scan results available — run the scan tool first", nil
	}

	var matched *findings.Finding
	items := pc.result.Findings.Findings()
	for i := range items {
		if items[i].Fingerprint == input.Fingerprint {
			matched = &items[i]
			break
		}
	}

	if matched == nil {
		return fmt.Sprintf("Error: finding with fingerprint %q not found in scan results", input.Fingerprint), nil
	}

	blPath := baseline.DefaultPath(input.Path)
	bl, err := baseline.Load(blPath)
	if err != nil {
		return "Error: loading baseline: " + err.Error(), nil
	}

	bl.Add(&baseline.Entry{
		Fingerprint: matched.Fingerprint,
		RuleID:      matched.RuleID,
		FilePath:    matched.Location.FilePath,
		Severity:    matched.Severity,
		Reason:      input.Reason,
		CreatedAt:   time.Now().UTC(),
	})

	if err := bl.Save(blPath); err != nil {
		return "Error: saving baseline: " + err.Error(), nil
	}

	return fmt.Sprintf("Added finding %s to baseline (%d total entries)", input.Fingerprint[:12], bl.Len()), nil
}

// Diff handler.

func (s *Server) handleDiff(_ context.Context, input diffInput) (string, error) {
	if input.Path == "" {
		return "Error: missing required argument: path", nil
	}

	if err := s.isPathAllowed(input.Path); err != nil {
		return "Error: " + err.Error(), nil
	}

	base := input.Base
	if base == "" {
		base = "main"
	}
	head := input.Head
	if head == "" {
		head = "HEAD"
	}

	result, err := diff.Run(input.Path, diff.Options{
		Base: base,
		Head: head,
	})
	if err != nil {
		return "Error: diff failed: " + err.Error(), nil
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "Error: marshalling diff result: " + err.Error(), nil
	}

	return truncate(string(data)), nil
}

// Badge handler.

func (s *Server) handleBadge(_ context.Context, input badgeInput) (string, error) {
	pc := s.getCache("")
	if pc == nil {
		return "Error: no scan results available — run the scan tool first", nil
	}

	label := input.Label
	if label == "" {
		label = "nox"
	}
	ff := pc.result.Findings.ActiveFindings()

	result := badge.GenerateFromFindings(ff, label)

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "Error: marshalling badge result: " + err.Error(), nil
	}

	return truncate(string(data)), nil
}

// Version handler.

func (s *Server) handleVersion(_ context.Context, _ emptyInput) (string, error) {
	info := map[string]string{
		"version": s.version,
	}

	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshalling version: %w", err)
	}

	return string(data), nil
}

// Rules handler.

func (s *Server) handleRules(_ context.Context, _ emptyInput) (string, error) {
	cat := catalog.Catalog()

	data, err := json.MarshalIndent(cat, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshalling rules: %w", err)
	}

	return truncate(string(data)), nil
}

// Protect status handler.

const noxHookMarker = "Installed by nox protect"

func (s *Server) handleProtectStatus(_ context.Context, input protectStatusInput) (string, error) {
	if input.Path == "" {
		return "Error: missing required argument: path", nil
	}

	if err := s.isPathAllowed(input.Path); err != nil {
		return "Error: " + err.Error(), nil
	}

	if !git.IsGitRepo(input.Path) {
		return "Error: not a git repository", nil
	}

	repoRoot, err := git.RepoRoot(input.Path)
	if err != nil {
		return "Error: resolving repo root: " + err.Error(), nil
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
		return string(data), nil
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
	return string(data), nil
}

// Annotate handler.

func (s *Server) handleAnnotate(_ context.Context, _ emptyInput) (string, error) {
	pc := s.getCache("")
	if pc == nil {
		return "Error: no scan results available — run the scan tool first", nil
	}

	ff := pc.result.Findings.ActiveFindings()
	payload := annotate.BuildReviewPayload(ff)
	if payload == nil {
		return `{"message":"no findings to annotate"}`, nil
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "Error: marshalling annotate payload: " + err.Error(), nil
	}

	return truncate(string(data)), nil
}

// VEX status handler.

func (s *Server) handleVEXStatus(_ context.Context, input vexStatusInput) (string, error) {
	if input.Path == "" {
		return "Error: missing required argument: path", nil
	}

	if err := s.isPathAllowed(input.Path); err != nil {
		return "Error: " + err.Error(), nil
	}

	doc, err := vex.LoadVEX(input.Path)
	if err != nil {
		return "Error: loading VEX document: " + err.Error(), nil
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
		Path:       input.Path,
		Statements: len(doc.Statements),
		ByStatus:   byStatus,
		Summary:    vex.Summary(doc),
	}

	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return "Error: marshalling response: " + err.Error(), nil
	}

	return string(data), nil
}

// Data sensitivity report handler.

func (s *Server) handleDataSensitivityReport(_ context.Context, _ emptyInput) (string, error) {
	pc := s.getCache("")
	if pc == nil {
		return "Error: no scan results available — run the scan tool first", nil
	}

	// Filter DATA-* findings from active findings.
	type ruleStats struct {
		RuleID      string   `json:"rule_id"`
		Description string   `json:"description"`
		Count       int      `json:"count"`
		Files       []string `json:"files"`
	}
	type rpt struct {
		TotalFindings int         `json:"total_findings"`
		Rules         []ruleStats `json:"rules"`
		AffectedFiles []string    `json:"affected_files"`
	}

	ruleMap := make(map[string]*ruleStats)
	allFiles := make(map[string]struct{})
	cat := catalog.Catalog()

	activeFindings := pc.result.Findings.ActiveFindings()
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

	r := rpt{
		TotalFindings: total,
		Rules:         rules,
		AffectedFiles: affectedFiles,
	}

	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "Error: marshalling report: " + err.Error(), nil
	}

	return truncate(string(data)), nil
}

// Dashboard tool handler.

func (s *Server) handleDashboard(_ context.Context, input dashboardInput) (string, error) {
	pc := s.getCache(input.Path)
	if pc == nil {
		return "Error: no scan results available", nil
	}

	html, err := GenerateDashboardHTML(pc.result, s.version, pc.basePath)
	if err != nil {
		return "", fmt.Errorf("generating dashboard: %w", err)
	}

	return html, nil
}

// Plugin bridge handlers.

func (s *Server) handlePluginList(_ context.Context, _ emptyInput) (string, error) {
	if s.host == nil {
		return "Error: no plugin host configured", nil
	}

	data, err := serializePluginList(s.host.Plugins())
	if err != nil {
		return "Error: serializing plugin list: " + err.Error(), nil
	}

	return truncate(string(data)), nil
}

func (s *Server) handlePluginCallTool(ctx context.Context, input pluginCallToolInput) (string, error) {
	if s.host == nil {
		return "Error: no plugin host configured", nil
	}

	if input.Tool == "" {
		return "Error: missing required argument: tool", nil
	}

	toolName := s.resolveToolName(input.Tool)

	if input.WorkspaceRoot != "" {
		if err := s.isPathAllowed(input.WorkspaceRoot); err != nil {
			return "Error: " + err.Error(), nil
		}
	}

	resp, err := s.host.InvokeTool(ctx, toolName, input.Input, input.WorkspaceRoot)
	if err != nil {
		if _, ok := err.(plugin.RuntimeViolation); ok {
			return "Error: plugin violation: " + err.Error(), nil
		}
		return "Error: plugin tool invocation failed: " + err.Error(), nil
	}

	data, err := serializeInvokeResult(resp)
	if err != nil {
		return "Error: serializing plugin response: " + err.Error(), nil
	}

	return truncate(string(data)), nil
}

func (s *Server) handlePluginReadResource(_ context.Context, _ pluginReadResourceInput) (string, error) {
	return "Error: plugin.read_resource is not yet implemented", nil
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

// --- Resource handlers ---

func (s *Server) handleResourceFindings(_ context.Context, uri string, _ map[string]string) (*mcp.ResourceContent, error) {
	pc := s.getCache("")
	if pc == nil {
		return nil, fmt.Errorf("no scan results available")
	}

	r := report.NewJSONReporter(s.version)
	data, err := r.Generate(pc.result.Findings)
	if err != nil {
		return nil, fmt.Errorf("generating findings JSON: %w", err)
	}

	return &mcp.ResourceContent{
		URI:      uri,
		MimeType: "application/json",
		Text:     truncate(string(data)),
	}, nil
}

func (s *Server) handleResourceSARIF(_ context.Context, uri string, _ map[string]string) (*mcp.ResourceContent, error) {
	pc := s.getCache("")
	if pc == nil {
		return nil, fmt.Errorf("no scan results available")
	}

	r := sarif.NewReporter(s.version, nil)
	data, err := r.Generate(pc.result.Findings)
	if err != nil {
		return nil, fmt.Errorf("generating SARIF: %w", err)
	}

	return &mcp.ResourceContent{
		URI:      uri,
		MimeType: "application/json",
		Text:     truncate(string(data)),
	}, nil
}

func (s *Server) handleResourceCDX(_ context.Context, uri string, _ map[string]string) (*mcp.ResourceContent, error) {
	pc := s.getCache("")
	if pc == nil {
		return nil, fmt.Errorf("no scan results available")
	}

	r := sbom.NewCycloneDXReporter(s.version)
	data, err := r.Generate(pc.result.Inventory)
	if err != nil {
		return nil, fmt.Errorf("generating CycloneDX SBOM: %w", err)
	}

	return &mcp.ResourceContent{
		URI:      uri,
		MimeType: "application/json",
		Text:     truncate(string(data)),
	}, nil
}

func (s *Server) handleResourceSPDX(_ context.Context, uri string, _ map[string]string) (*mcp.ResourceContent, error) {
	pc := s.getCache("")
	if pc == nil {
		return nil, fmt.Errorf("no scan results available")
	}

	r := sbom.NewSPDXReporter(s.version)
	data, err := r.Generate(pc.result.Inventory)
	if err != nil {
		return nil, fmt.Errorf("generating SPDX SBOM: %w", err)
	}

	return &mcp.ResourceContent{
		URI:      uri,
		MimeType: "application/json",
		Text:     truncate(string(data)),
	}, nil
}

func (s *Server) handleResourceAIInventory(_ context.Context, uri string, _ map[string]string) (*mcp.ResourceContent, error) {
	pc := s.getCache("")
	if pc == nil {
		return nil, fmt.Errorf("no scan results available")
	}

	data, err := pc.result.AIInventory.JSON()
	if err != nil {
		return nil, fmt.Errorf("generating AI inventory JSON: %w", err)
	}

	return &mcp.ResourceContent{
		URI:      uri,
		MimeType: "application/json",
		Text:     truncate(string(data)),
	}, nil
}

func (s *Server) handleResourceRules(_ context.Context, uri string, _ map[string]string) (*mcp.ResourceContent, error) {
	cat := catalog.Catalog()

	data, err := json.MarshalIndent(cat, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshalling rules: %w", err)
	}

	return &mcp.ResourceContent{
		URI:      uri,
		MimeType: "application/json",
		Text:     truncate(string(data)),
	}, nil
}

func (s *Server) handleResourceDashboard(_ context.Context, uri string, _ map[string]string) (*mcp.ResourceContent, error) {
	pc := s.getCache("")
	if pc == nil {
		return nil, fmt.Errorf("no scan results available")
	}

	html, err := GenerateDashboardHTML(pc.result, s.version, pc.basePath)
	if err != nil {
		return nil, fmt.Errorf("generating dashboard: %w", err)
	}

	return &mcp.ResourceContent{
		URI:      uri,
		MimeType: "text/html",
		Text:     html,
	}, nil
}

// --- Per-project resource handlers ---

func (s *Server) resolveProjectPath(params map[string]string) (string, error) {
	project, ok := params["project"]
	if !ok || project == "" {
		return "", fmt.Errorf("missing project parameter")
	}
	path, err := url.PathUnescape(project)
	if err != nil {
		return "", fmt.Errorf("invalid project path: %w", err)
	}
	return path, nil
}

func (s *Server) handleProjectResourceFindings(_ context.Context, uri string, params map[string]string) (*mcp.ResourceContent, error) {
	path, err := s.resolveProjectPath(params)
	if err != nil {
		return nil, err
	}
	pc := s.getCache(path)
	if pc == nil {
		return nil, fmt.Errorf("no scan results for project %q", path)
	}

	r := report.NewJSONReporter(s.version)
	data, err := r.Generate(pc.result.Findings)
	if err != nil {
		return nil, fmt.Errorf("generating findings JSON: %w", err)
	}

	return &mcp.ResourceContent{
		URI:      uri,
		MimeType: "application/json",
		Text:     truncate(string(data)),
	}, nil
}

func (s *Server) handleProjectResourceSARIF(_ context.Context, uri string, params map[string]string) (*mcp.ResourceContent, error) {
	path, err := s.resolveProjectPath(params)
	if err != nil {
		return nil, err
	}
	pc := s.getCache(path)
	if pc == nil {
		return nil, fmt.Errorf("no scan results for project %q", path)
	}

	r := sarif.NewReporter(s.version, nil)
	data, err := r.Generate(pc.result.Findings)
	if err != nil {
		return nil, fmt.Errorf("generating SARIF: %w", err)
	}

	return &mcp.ResourceContent{
		URI:      uri,
		MimeType: "application/json",
		Text:     truncate(string(data)),
	}, nil
}

func (s *Server) handleProjectResourceCDX(_ context.Context, uri string, params map[string]string) (*mcp.ResourceContent, error) {
	path, err := s.resolveProjectPath(params)
	if err != nil {
		return nil, err
	}
	pc := s.getCache(path)
	if pc == nil {
		return nil, fmt.Errorf("no scan results for project %q", path)
	}

	r := sbom.NewCycloneDXReporter(s.version)
	data, err := r.Generate(pc.result.Inventory)
	if err != nil {
		return nil, fmt.Errorf("generating CycloneDX SBOM: %w", err)
	}

	return &mcp.ResourceContent{
		URI:      uri,
		MimeType: "application/json",
		Text:     truncate(string(data)),
	}, nil
}

func (s *Server) handleProjectResourceSPDX(_ context.Context, uri string, params map[string]string) (*mcp.ResourceContent, error) {
	path, err := s.resolveProjectPath(params)
	if err != nil {
		return nil, err
	}
	pc := s.getCache(path)
	if pc == nil {
		return nil, fmt.Errorf("no scan results for project %q", path)
	}

	r := sbom.NewSPDXReporter(s.version)
	data, err := r.Generate(pc.result.Inventory)
	if err != nil {
		return nil, fmt.Errorf("generating SPDX SBOM: %w", err)
	}

	return &mcp.ResourceContent{
		URI:      uri,
		MimeType: "application/json",
		Text:     truncate(string(data)),
	}, nil
}

func (s *Server) handleProjectResourceAIInventory(_ context.Context, uri string, params map[string]string) (*mcp.ResourceContent, error) { // nox:ignore SEC-659 -- function name, not a key
	path, err := s.resolveProjectPath(params)
	if err != nil {
		return nil, err
	}
	pc := s.getCache(path)
	if pc == nil {
		return nil, fmt.Errorf("no scan results for project %q", path)
	}

	data, err := pc.result.AIInventory.JSON()
	if err != nil {
		return nil, fmt.Errorf("generating AI inventory JSON: %w", err)
	}

	return &mcp.ResourceContent{
		URI:      uri,
		MimeType: "application/json",
		Text:     truncate(string(data)),
	}, nil
}

func (s *Server) handleProjectResourceDashboard(_ context.Context, uri string, params map[string]string) (*mcp.ResourceContent, error) {
	path, err := s.resolveProjectPath(params)
	if err != nil {
		return nil, err
	}
	pc := s.getCache(path)
	if pc == nil {
		return nil, fmt.Errorf("no scan results for project %q", path)
	}

	html, err := GenerateDashboardHTML(pc.result, s.version, pc.basePath)
	if err != nil {
		return nil, fmt.Errorf("generating dashboard: %w", err)
	}

	return &mcp.ResourceContent{
		URI:      uri,
		MimeType: "text/html",
		Text:     html,
	}, nil
}

// --- plugin_install handler ---

func (s *Server) handlePluginInstall(_ context.Context, input pluginInstallInput) (string, error) {
	if input.Name == "" {
		return "Error: missing required argument: name (e.g. nox/ai-eval)", nil
	}
	// Reject obviously suspicious names so a hostile prompt can't tunnel
	// arbitrary args into the subprocess. Plugin names are restricted to
	// the registry's character set.
	if !isSafePluginName(input.Name) {
		return "Error: invalid plugin name (allowed chars: a-z, 0-9, /, -, _, .)", nil
	}
	if input.Version != "" && !isSafeVersionConstraint(input.Version) {
		return "Error: invalid version constraint", nil
	}

	noxBin, err := os.Executable()
	if err != nil {
		return "Error: locating nox binary: " + err.Error(), nil
	}

	spec := input.Name
	if input.Version != "" {
		spec = input.Name + "@" + input.Version
	}

	cmd := exec.Command(noxBin, "plugin", "install", spec)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Plugin install failed: %v\n\nOutput:\n%s", err, string(out)), nil
	}
	return "Plugin install:\n" + string(out), nil
}

// isSafePluginName accepts only registry-shaped names so a hostile
// prompt can't smuggle shell metacharacters into an exec.Command call.
// Path-traversal sequences (..) and leading dots are rejected even
// though the underlying chars are otherwise allowed.
func isSafePluginName(s string) bool {
	if s == "" || len(s) > 200 {
		return false
	}
	if strings.Contains(s, "..") {
		return false
	}
	if s[0] == '.' || s[0] == '-' || s[0] == '/' {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '/' || r == '-' || r == '_' || r == '.':
		default:
			return false
		}
	}
	return true
}

// isSafeVersionConstraint accepts a constrained subset of semver-shaped
// strings: digits, dots, hyphens, plus, ASCII letters (for prerelease
// identifiers like 1.0.0-beta), and the range operators >= ^ ~.
func isSafeVersionConstraint(s string) bool {
	if s == "" || len(s) > 50 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r == '.' || r == '-' || r == '+' || r == '>' || r == '=' || r == '^' || r == '~':
		default:
			return false
		}
	}
	return true
}

// truncate limits output to maxOutputBytes, appending a truncation notice if needed.
func truncate(s string) string {
	if len(s) <= maxOutputBytes {
		return s
	}
	return s[:maxOutputBytes] + "\n... [truncated: output exceeded 1MB limit]"
}

// --- fix_plan / agent_graph handlers ---

// fixAction is the wire shape for a single planned upgrade. Mirrors
// cli's upgradeAction but JSON-tagged for MCP transport.
type fixAction struct {
	RuleID    string `json:"rule_id"`
	Package   string `json:"package"`
	From      string `json:"from"`
	To        string `json:"to"`
	Ecosystem string `json:"ecosystem"`
	Command   string `json:"command"`
}

type fixPlanResponse struct {
	Actions      []fixAction `json:"actions"`
	Skipped      int         `json:"skipped"`
	MajorSkipped int         `json:"major_skipped"`
	Note         string      `json:"note,omitempty"`
}

func (s *Server) handleFixPlan(_ context.Context, input fixPlanInput) (string, error) {
	pc := s.getCache("")
	if pc == nil {
		return "Error: no scan results available — run the scan tool first", nil
	}

	resp := fixPlanResponse{
		Note: "Plan only. Apply with: nox fix --input findings.json",
	}

	seen := map[string]bool{}
	items := pc.result.Findings.ActiveFindings()
	for i := range items {
		f := &items[i]
		if f.RuleID != "VULN-001" {
			continue
		}
		fixed := f.Metadata["fixed_in"]
		eco := f.Metadata["ecosystem"]
		pkg := f.Metadata["package"]
		from := f.Metadata["version"]
		if fixed == "" || pkg == "" || eco == "" {
			resp.Skipped++
			continue
		}
		if !input.IncludeMajor && majorOfVersion(from) != majorOfVersion(fixed) && from != "" {
			resp.MajorSkipped++
			continue
		}
		key := pkg + "@" + fixed
		if seen[key] {
			continue
		}
		seen[key] = true
		resp.Actions = append(resp.Actions, fixAction{
			RuleID:    f.RuleID,
			Package:   pkg,
			From:      from,
			To:        fixed,
			Ecosystem: eco,
			Command:   commandFor(eco, pkg, fixed),
		})
	}

	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return "Error: marshalling plan: " + err.Error(), nil
	}
	return truncate(string(data)), nil
}

// majorOfVersion returns the leading numeric segment of a semver-ish
// version string ("v1.2.3" -> "1", "" -> "").
func majorOfVersion(v string) string {
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexByte(v, '.'); i >= 0 {
		v = v[:i]
	}
	return v
}

// commandFor returns the canonical operator-runnable upgrade command
// for a (ecosystem, package, version) tuple. Mirrors cli's
// upgradeCommand but lives here to avoid pulling cli/ into server/.
func commandFor(eco, pkg, fixedVer string) string {
	v := strings.TrimPrefix(fixedVer, "v")
	switch eco {
	case "go":
		return "go get " + pkg + "@v" + v
	case "npm":
		return "npm install " + pkg + "@" + v
	case "pypi":
		return "pip install '" + pkg + ">=" + v + "'"
	case "rubygems":
		return "bundle update " + pkg + " --conservative"
	case "cargo":
		return "cargo update -p " + pkg + " --precise " + v
	case "maven", "gradle":
		return "upgrade " + pkg + " to " + v + " in your build file"
	case "nuget":
		return "dotnet add package " + pkg + " --version " + v
	}
	return ""
}

func (s *Server) handleAgentGraph(_ context.Context, input agentGraphInput) (string, error) {
	pc := s.getCache("")
	if pc == nil {
		return "Error: no scan results available — run the scan tool first", nil
	}
	if pc.result.AIInventory == nil || len(pc.result.AIInventory.ToolMatrix) == 0 {
		return "No agent tool registrations detected. Run scan on a project with agent code first.", nil
	}

	format := input.Format
	if format == "" {
		format = "mermaid"
	}
	switch format {
	case "mermaid":
		return renderMermaidGraph(pc.result.AIInventory), nil
	case "dot":
		return renderDotGraph(pc.result.AIInventory), nil
	default:
		return "Error: unknown format " + format + " (use mermaid or dot)", nil
	}
}

func renderMermaidGraph(inv *ai.Inventory) string {
	var b strings.Builder
	b.WriteString("graph LR\n")
	for i, set := range inv.ToolMatrix {
		fmt.Fprintf(&b, "    subgraph agent%d [%s]\n", i, sanitiseGraph(set.Agent))
		for j, tool := range set.Tools {
			caps := graphCaps(set.Capabilities[tool])
			label := tool
			if caps != "" {
				label = label + "<br/><small>" + caps + "</small>"
			}
			fmt.Fprintf(&b, "        a%d_t%d[\"%s\"]\n", i, j, label)
		}
		b.WriteString("    end\n")
	}
	return b.String()
}

func renderDotGraph(inv *ai.Inventory) string {
	var b strings.Builder
	b.WriteString("digraph nox_agent_lattice {\n")
	b.WriteString("    rankdir=LR;\n    node [shape=box, style=rounded];\n")
	for i, set := range inv.ToolMatrix {
		fmt.Fprintf(&b, "    subgraph cluster_%d {\n        label=%q;\n", i, set.Agent)
		for j, tool := range set.Tools {
			caps := graphCaps(set.Capabilities[tool])
			label := tool
			if caps != "" {
				label = tool + "\\n[" + caps + "]"
			}
			fmt.Fprintf(&b, "        a%d_t%d [label=%q];\n", i, j, label)
		}
		b.WriteString("    }\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func sanitiseGraph(s string) string {
	r := strings.NewReplacer("\"", "'", "\n", " ", "[", "(", "]", ")")
	return r.Replace(s)
}

func graphCaps(caps []string) string {
	if len(caps) == 0 {
		return ""
	}
	cp := make([]string, len(caps))
	copy(cp, caps)
	sort.Strings(cp)
	return strings.Join(cp, ",")
}
