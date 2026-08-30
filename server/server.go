// Package server implements the MCP server for agent-safe artifact serving.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nox-hq/nox/core/dashboard"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/annotate"
	"github.com/nox-hq/nox/core/badge"
	"github.com/nox-hq/nox/core/baseline"
	"github.com/nox-hq/nox/core/catalog"
	"github.com/nox-hq/nox/core/detail"
	"github.com/nox-hq/nox/core/diff"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/fix"
	"github.com/nox-hq/nox/core/git"
	"github.com/nox-hq/nox/core/report"
	"github.com/nox-hq/nox/core/report/sarif"
	"github.com/nox-hq/nox/core/report/sbom"
	"github.com/nox-hq/nox/core/vex"
	"github.com/nox-hq/nox/plugin"
	mcp "go.klarlabs.de/mcp"
)

const (
	// maxOutputBytes is the maximum response size before truncation (1 MB).
	maxOutputBytes = 1 << 20
	// maxListLimit caps a single list_findings page so the response stays well
	// under maxOutputBytes even with rule metadata enriched per finding.
	maxListLimit = 500
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
	Offset            float64 `json:"offset,omitempty"`
	IncludeSuppressed bool    `json:"include_suppressed,omitempty"`
}
type findingByFingerprintInput struct {
	Fingerprint string `json:"fingerprint"`
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
	Name    string `json:"name"`              // required: nox/foo or nox-plugin-foo
	Version string `json:"version,omitempty"` // optional version constraint
	// Confirmed must be true for the install to proceed. The MCP host
	// (e.g. Claude Desktop) is responsible for collecting operator
	// consent before forwarding the call. A hostile prompt asking the
	// LLM to install a plugin without confirmation hits this gate and
	// fails closed. Boolean rather than a free-form string so prompt
	// engineering can't talk the LLM into auto-supplying consent text.
	Confirmed bool `json:"confirmed"`
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
		OutputSchema(detail.FindingDetail{}).
		Handler(s.handleGetFindingDetail)

	// Track D and Milestone 9.3 reach the agent surface here. Both are
	// read-only and both answer a question the existing tools cannot: what was
	// never evaluated, and why a finding was reported.
	srv.Tool("analysis_capabilities").
		Description("What this installation can establish and what THIS scan actually established, per analysis capability. Call it before summarising a scan: a capability that is provided but answered nothing was available and never used, which is not a clean result — it means the question was not asked. Degradations tell you a check broke; this tells you a question was never put.").
		ReadOnly().
		OutputSchema(capabilityOutput{}).
		Handler(s.handleAnalysisCapabilities)

	srv.Tool("why").
		Description("Answer eight questions about a finding: what was observed, why it matters, what supports it, what argues against it, what was NOT evaluated, the potential impact, whether it affects this application, and what to do. Deterministic — derived from what the scan established, not written by a model. Pass a fingerprint (full or prefix) or a rule ID; omit to explain every active finding.").
		ReadOnly().
		OutputSchema(whyOutput{}).
		Handler(s.handleWhy)

	srv.Tool("summary").
		Description("Aggregate overview of the last scan: active/total/suppressed counts and breakdowns by severity, confidence, and rule family, plus dependency and AI-component totals. Call this first to size up a scan before paging through individual findings.").
		ReadOnly().
		OutputSchema(summaryOutput{}).
		Handler(s.handleSummary)

	srv.Tool("list_findings").
		Description("List findings with optional severity, rule, and file filters. Paginated: pass limit (default 50, max 500) and offset to page through a large result set. Returns an envelope {total, offset, limit, returned, has_more, findings} so you know how many findings exist and whether more pages remain.").
		ReadOnly().
		OutputSchema(listFindingsOutput{}).
		Handler(s.handleListFindings)

	srv.Tool("get_finding_by_fingerprint").
		Description("Look up a single finding by fingerprint (full or 12-char prefix) and report its current status (new / baselined / suppressed / vex_*). Use this when you already hold a fingerprint (from a prior scan or baseline entry) and just need to know whether it is still active. Returns {found:false, fingerprint} if no match.").
		ReadOnly().
		OutputSchema(fingerprintLookupOutput{}).
		Handler(s.handleFindingByFingerprint)

	srv.Tool("baseline_status").
		Description("Show baseline statistics: total entries, expired count, per-severity breakdown").
		ReadOnly().
		OutputSchema(baselineStatusOutput{}).
		Handler(s.handleBaselineStatus)

	srv.Tool("baseline_add").
		Description("Add a finding to the baseline by fingerprint").
		Handler(s.handleBaselineAdd)

	srv.Tool("baseline_add_many").
		Description("Batch-suppress multiple findings by fingerprint in a single call. Saves the baseline once and updates the cached scan results so list_findings/badge reflect the new state without a re-scan.").
		Handler(s.handleBaselineAddMany)

	srv.Tool("diff").
		Description("Scan only changed files between two git refs and return findings").
		ReadOnly().
		OutputSchema(diff.Result{}).
		Handler(s.handleDiff)

	srv.Tool("badge").
		Description("Generate a security grade SVG badge from the last scan").
		ReadOnly().
		Handler(s.handleBadge)

	srv.Tool("version").
		Description("Return nox version, commit, and build date").
		ReadOnly().
		OutputSchema(versionOutput{}).
		Handler(s.handleVersion)

	srv.Tool("rules").
		Description("List all security rules with ID, description, severity, CWE, and remediation").
		ReadOnly().
		OutputSchema(rulesOutput{}).
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
		OutputSchema(vexStatusOutput{}).
		Handler(s.handleVEXStatus)

	srv.Tool("fix_plan").
		Description("Plan dependency upgrade actions from VULN-001 findings with fixed_in metadata. Read-only — returns the upgrade plan as a list; never mutates the workspace. Operators apply via the nox fix CLI subcommand.").
		ReadOnly().
		OutputSchema(fixPlanResponse{}).
		Handler(s.handleFixPlan)

	// Offline attack planning. The ACTIVE half of `nox attack` is deliberately
	// not registered — see the rationale at the top of server/attack.go.
	s.registerAttackTools(srv)

	srv.Tool("agent_graph").
		Description("Render the detected agent capability lattice as Mermaid (default) or Graphviz dot. Drop into a markdown file or render with dot to audit which tools each agent can call.").
		ReadOnly().
		Handler(s.handleAgentGraph)

	srv.Tool("plugin_install").
		Description("Install a nox plugin by name (e.g. nox/ai-eval). Resolves the plugin against configured registries, fetches the platform binary, verifies the digest, and registers it in local state. Network call; not read-only. REQUIRES `confirmed: true` — the MCP host MUST collect operator consent before forwarding this call. A plugin install runs new code on the operator's machine.").
		Handler(s.handlePluginInstall)

	srv.Tool("data_sensitivity_report").
		Description("Summarize PII and sensitive data findings from the scan (DATA-* rules)").
		ReadOnly().
		OutputSchema(report.DataSensitivityReport{}).
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

	// plugin.read_resource is deliberately NOT registered. Plugins declare their
	// resources in their manifest, but PluginService has no resource-read RPC
	// (GetManifest / InvokeTool / StreamArtifacts only), so nothing can serve
	// one. It used to be registered with the description "Read a resource from a
	// plugin" and a handler that returned "not yet implemented" as a SUCCESSFUL
	// result — an agent reading isError saw success. A capability nox cannot
	// deliver must not appear in tools/list at all; see
	// TestNoRegisteredToolIsAStub.
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
		Handler(s.handleProjectResourceAIInventory)

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

	// RecordReasoning, not RunScan's default. The `why` tool answers from the
	// evidence a scan gathers, and that evidence cannot be reconstructed
	// afterwards — a scan that did not record it can only report that it did
	// not. An agent surface is precisely where being able to ask "why" is worth
	// the cost, and the ledger is held out-of-band so a finding still carries
	// no extra bytes.
	result, err := nox.RunScanWithOptions(input.Path, nox.ScanOptions{RecordReasoning: true})
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
		// Degradations must ride the artifact here above all: an agent has no
		// stderr to read, so without this it cannot tell a clean scan from one
		// whose checks did not run.
		r.Degradations = report.DegradationsFrom(pc.result.Degradations)
		data, err = r.Generate(pc.result.Findings)
	}

	if err != nil {
		return "Error: report generation failed: " + err.Error(), nil
	}

	// Never hand back a mid-structure truncation: a clipped SARIF/JSON document
	// is unparseable and the agent has no signal that data was lost. When the
	// full report exceeds the budget, return a structured pointer to the
	// paginated list_findings tool instead.
	if len(data) > maxOutputBytes {
		notice, _ := json.MarshalIndent(map[string]any{
			"error":       "output_too_large",
			"total_bytes": len(data),
			"limit_bytes": maxOutputBytes,
			"hint":        "the full report exceeds the response budget — use list_findings with limit/offset to page through findings, or get a specific finding with get_finding_detail",
		}, "", "  ")
		return string(notice), nil
	}

	return string(data), nil
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

func (s *Server) handleGetFindingDetail(_ context.Context, input getFindingDetailInput) (mcp.StructuredResult, error) {
	pc := s.getCache("")
	if pc == nil {
		return toolError("no scan results available — run the scan tool first"), nil
	}

	if input.FindingID == "" {
		return toolError("missing required argument: finding_id"), nil
	}

	contextLines := 5
	if input.ContextLines > 0 {
		contextLines = int(input.ContextLines)
	}

	store := detail.LoadFromSet(pc.result.Findings, pc.basePath)
	f, ok := store.ByID(input.FindingID)
	if !ok {
		return toolError(fmt.Sprintf("finding %q not found", input.FindingID)), nil
	}

	cat := catalog.Catalog()
	enriched := detail.Enrich(&f, pc.basePath, store.All(), cat, contextLines)

	return structured(enriched)
}

// handleSummary returns an aggregate overview of the last scan: counts by
// severity, confidence, and rule family, plus dependency / AI-component totals.
// This is the cheap "what am I looking at?" call an agent (or human) makes
// before deciding whether to page through individual findings.
func (s *Server) handleSummary(_ context.Context, _ emptyInput) (mcp.StructuredResult, error) {
	pc := s.getCache("")
	if pc == nil {
		return toolError("no scan results available — run the scan tool first"), nil
	}

	active := pc.result.Findings.ActiveFindings()
	total := len(pc.result.Findings.Findings())

	bySeverity := map[string]int{}
	byConfidence := map[string]int{}
	byFamily := map[string]int{}
	for i := range active {
		f := &active[i]
		bySeverity[string(f.Severity)]++
		byConfidence[string(f.Confidence)]++
		byFamily[ruleFamily(f.RuleID)]++
	}

	return structured(summaryOutput{
		ActiveFindings: len(active),
		TotalFindings:  total,
		Suppressed:     total - len(active),
		BySeverity:     bySeverity,
		ByConfidence:   byConfidence,
		ByFamily:       byFamily,
		Dependencies:   len(pc.result.Inventory.Packages()),
		AIComponents:   len(pc.result.AIInventory.Components),
	})
}

// ruleFamily maps a rule ID (e.g. "SEC-001", "VULN-002") to its human family
// name, used for grouping in the summary.
func ruleFamily(ruleID string) string { return catalog.Family(ruleID).Key }

// handleFindingByFingerprint looks up a single finding by its fingerprint and
// reports its current status (new / baselined / suppressed / vex_*). This is
// the O(1)-style call an agent makes when it already holds a fingerprint (from
// a prior scan or a baseline entry) and wants to know whether that finding is
// still active — without pulling and searching the full findings list. Accepts
// a full fingerprint or a unique prefix (the 12-char form used in finding IDs).
func (s *Server) handleFindingByFingerprint(_ context.Context, input findingByFingerprintInput) (mcp.StructuredResult, error) {
	if strings.TrimSpace(input.Fingerprint) == "" {
		return toolError("missing required argument: fingerprint"), nil
	}
	pc := s.getCache("")
	if pc == nil {
		return toolError("no scan results available — run the scan tool first"), nil
	}

	fp := strings.TrimSpace(input.Fingerprint)
	all := pc.result.Findings.Findings()
	for i := range all {
		f := &all[i]
		if f.Addresses(fp) {
			loc := f.Location
			return structured(fingerprintLookupOutput{
				Found:       true,
				ID:          f.ID,
				Fingerprint: f.Fingerprint,
				RuleID:      f.RuleID,
				Severity:    f.Severity,
				Confidence:  f.Confidence,
				Status:      statusOrNew(f.Status),
				Message:     f.Message,
				Location:    &loc,
			})
		}
	}
	return structured(fingerprintLookupOutput{
		Found:       false,
		Fingerprint: fp,
	})
}

// statusOrNew reports a finding's status, defaulting an empty status to "new".
func statusOrNew(st findings.Status) findings.Status {
	if st == "" {
		return findings.StatusNew
	}
	return st
}

func (s *Server) handleListFindings(_ context.Context, input listFindingsInput) (mcp.StructuredResult, error) {
	pc := s.getCache("")
	if pc == nil {
		return toolError("no scan results available — run the scan tool first"), nil
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
	total := len(filtered)

	// Apply offset + limit so an agent can page through a large result set
	// deterministically (findings come back in a stable sorted order). Default
	// page size 50; capped at maxListLimit to keep one response well under the
	// MCP output budget.
	limit := 50
	if input.Limit > 0 {
		limit = int(input.Limit)
	}
	if limit > maxListLimit {
		limit = maxListLimit
	}
	offset := 0
	if input.Offset > 0 {
		offset = int(input.Offset)
	}
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	page := filtered[offset:end]

	// Enrich each finding with rule metadata.
	results := make([]enrichedFinding, 0, len(page))
	for i := range page {
		f := &page[i]
		fs := enrichedFinding{Finding: *f}
		if meta, ok := cat[f.RuleID]; ok {
			fs.Rule = &meta
		}
		results = append(results, fs)
	}

	// The envelope carries pagination metadata so the caller knows the total
	// and whether more pages remain — instead of silently receiving a truncated
	// slice with no signal.
	return structured(listFindingsOutput{
		Total:    total,
		Offset:   offset,
		Limit:    limit,
		Returned: len(results),
		HasMore:  end < total,
		Findings: results,
	})
}

// Baseline handlers.

func (s *Server) handleBaselineStatus(_ context.Context, input baselineStatusInput) (mcp.StructuredResult, error) {
	if input.Path == "" {
		return toolError("missing required argument: path"), nil
	}

	if err := s.isPathAllowed(input.Path); err != nil {
		return toolError(err.Error()), nil
	}

	bl, err := baseline.Load(baseline.DefaultPath(input.Path))
	if err != nil {
		return toolError("loading baseline: " + err.Error()), nil
	}

	st := bl.Status()
	bySev := make(map[string]int, len(st.BySeverity))
	for sev, n := range st.BySeverity {
		bySev[string(sev)] = n
	}

	return structured(baselineStatusOutput{
		Total:      st.Total,
		Expired:    st.Expired,
		BySeverity: bySev,
		Path:       baseline.DefaultPath(input.Path),
	})
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

	matchedIdx := -1
	items := pc.result.Findings.Findings()
	for i := range items {
		if items[i].Fingerprint == input.Fingerprint {
			matchedIdx = i
			break
		}
	}

	if matchedIdx < 0 {
		return fmt.Sprintf("Error: finding with fingerprint %q not found in scan results", input.Fingerprint), nil
	}
	matched := &items[matchedIdx]

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

	// Invalidate the cached finding's status so subsequent list_findings /
	// badge calls reflect the suppression without requiring a re-scan —
	// see issue #61 (1) and (4).
	pc.result.Findings.SetStatus(matchedIdx, findings.StatusBaselined)

	return fmt.Sprintf("Added finding %s to baseline (%d total entries)", input.Fingerprint[:12], bl.Len()), nil
}

// baselineAddManyInput supports batch suppression so an agent doing a
// baseline pass can avoid N round-trips per finding — see issue #61 (3).
type baselineAddManyInput struct {
	Path         string   `json:"path"`
	Fingerprints []string `json:"fingerprints"`
	Reason       string   `json:"reason"`
}

type baselineAddManyResponse struct {
	Path         string   `json:"path"`
	Added        int      `json:"added"`
	NotFound     []string `json:"not_found,omitempty"`
	BaselineSize int      `json:"baseline_size"`
}

func (s *Server) handleBaselineAddMany(_ context.Context, input baselineAddManyInput) (string, error) {
	if input.Path == "" {
		return "Error: missing required argument: path", nil
	}
	if err := s.isPathAllowed(input.Path); err != nil {
		return "Error: " + err.Error(), nil
	}
	if len(input.Fingerprints) == 0 {
		return "Error: missing required argument: fingerprints", nil
	}

	pc := s.getCache("")
	if pc == nil {
		return "Error: no scan results available — run the scan tool first", nil
	}

	blPath := baseline.DefaultPath(input.Path)
	bl, err := baseline.Load(blPath)
	if err != nil {
		return "Error: loading baseline: " + err.Error(), nil
	}

	now := time.Now().UTC()
	items := pc.result.Findings.Findings()

	// Build a lookup so the loop is O(N + M) instead of O(N*M).
	byFP := make(map[string]int, len(items))
	for i := range items {
		byFP[items[i].Fingerprint] = i
	}

	resp := baselineAddManyResponse{Path: blPath}
	for _, fp := range input.Fingerprints {
		idx, ok := byFP[fp]
		if !ok {
			resp.NotFound = append(resp.NotFound, fp)
			continue
		}
		f := &items[idx]
		bl.Add(&baseline.Entry{
			Fingerprint: f.Fingerprint,
			RuleID:      f.RuleID,
			FilePath:    f.Location.FilePath,
			Severity:    f.Severity,
			Reason:      input.Reason,
			CreatedAt:   now,
		})
		pc.result.Findings.SetStatus(idx, findings.StatusBaselined)
		resp.Added++
	}

	if err := bl.Save(blPath); err != nil {
		return "Error: saving baseline: " + err.Error(), nil
	}
	resp.BaselineSize = bl.Len()

	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return "Error: marshalling response: " + err.Error(), nil
	}
	return string(data), nil
}

// Diff handler.

func (s *Server) handleDiff(_ context.Context, input diffInput) (mcp.StructuredResult, error) {
	if input.Path == "" {
		return toolError("missing required argument: path"), nil
	}

	if err := s.isPathAllowed(input.Path); err != nil {
		return toolError(err.Error()), nil
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
		return toolError("diff failed: " + err.Error()), nil
	}

	return structured(result)
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

func (s *Server) handleVersion(_ context.Context, _ emptyInput) (mcp.StructuredResult, error) {
	return structured(versionOutput{Version: s.version})
}

// Rules handler.

func (s *Server) handleRules(_ context.Context, _ emptyInput) (mcp.StructuredResult, error) {
	cat := catalog.Catalog()

	ids := make([]string, 0, len(cat))
	for id := range cat {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	rules := make([]catalog.RuleMeta, 0, len(cat))
	for _, id := range ids {
		rules = append(rules, cat[id])
	}

	return structured(rulesOutput{Total: len(rules), Rules: rules})
}

// Protect status handler.

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

	type protectStatusResponse struct {
		Installed bool   `json:"installed"`
		HookPath  string `json:"hook_path"`
		Message   string `json:"message"`
	}

	state, hookPath := git.HookStatus(repoRoot)
	installed := state == git.HookNox
	msg := "not installed"
	switch state {
	case git.HookNox:
		msg = "installed"
	case git.HookForeign:
		msg = "not installed (pre-commit hook exists but was not installed by nox)"
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

func (s *Server) handleVEXStatus(_ context.Context, input vexStatusInput) (mcp.StructuredResult, error) {
	if input.Path == "" {
		return toolError("missing required argument: path"), nil
	}

	if err := s.isPathAllowed(input.Path); err != nil {
		return toolError(err.Error()), nil
	}

	doc, err := vex.LoadVEX(input.Path)
	if err != nil {
		return toolError("loading VEX document: " + err.Error()), nil
	}

	byStatus := make(map[string]int)
	for status, n := range vex.StatusCounts(doc) {
		byStatus[string(status)] = n
	}

	return structured(vexStatusOutput{
		Path:       input.Path,
		Statements: len(doc.Statements),
		ByStatus:   byStatus,
		Summary:    vex.Summary(doc),
	})
}

// Data sensitivity report handler.

func (s *Server) handleDataSensitivityReport(_ context.Context, _ emptyInput) (mcp.StructuredResult, error) {
	pc := s.getCache("")
	if pc == nil {
		return toolError("no scan results available — run the scan tool first"), nil
	}

	// The projection lives in core/report; the handler only injects the catalog
	// as the rule-description source and marshals the result.
	cat := catalog.Catalog()
	rep := report.BuildDataSensitivityReport(pc.result.Findings.ActiveFindings(), func(ruleID string) string {
		if meta, ok := cat[ruleID]; ok {
			return meta.Description
		}
		return ""
	})
	return structured(rep)
}

// Dashboard tool handler.

// dashboardTooLargeNotice returns a structured JSON notice mirroring the
// handleGetFindings "output_too_large" pattern. The dashboard is a single HTML
// document, so a mid-document truncate() would yield broken, unparseable markup
// with no signal to the caller that data was lost. Instead the dashboard
// handlers fail closed once the rendered HTML crosses the response budget and
// point the caller at the cheaper summary / list_findings tools.
func dashboardTooLargeNotice(size int) string {
	notice, _ := json.MarshalIndent(map[string]any{
		"error":       "output_too_large",
		"total_bytes": size,
		"limit_bytes": maxOutputBytes,
		"hint":        "the dashboard HTML exceeds the response budget — use summary for an aggregate overview, or list_findings with limit/offset to page through findings",
	}, "", "  ")
	return string(notice)
}

func (s *Server) handleDashboard(_ context.Context, input dashboardInput) (string, error) {
	pc := s.getCache(input.Path)
	if pc == nil {
		return "Error: no scan results available", nil
	}

	html, err := dashboard.GenerateHTML(pc.result, s.version, pc.basePath)
	if err != nil {
		return "", fmt.Errorf("generating dashboard: %w", err)
	}

	if len(html) > maxOutputBytes {
		return dashboardTooLargeNotice(len(html)), nil
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
	r.Degradations = report.DegradationsFrom(pc.result.Degradations)
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

	html, err := dashboard.GenerateHTML(pc.result, s.version, pc.basePath)
	if err != nil {
		return nil, fmt.Errorf("generating dashboard: %w", err)
	}

	if len(html) > maxOutputBytes {
		return &mcp.ResourceContent{
			URI:      uri,
			MimeType: "application/json",
			Text:     dashboardTooLargeNotice(len(html)),
		}, nil
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
	r.Degradations = report.DegradationsFrom(pc.result.Degradations)
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

func (s *Server) handleProjectResourceAIInventory(_ context.Context, uri string, params map[string]string) (*mcp.ResourceContent, error) {
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

	html, err := dashboard.GenerateHTML(pc.result, s.version, pc.basePath)
	if err != nil {
		return nil, fmt.Errorf("generating dashboard: %w", err)
	}

	if len(html) > maxOutputBytes {
		return &mcp.ResourceContent{
			URI:      uri,
			MimeType: "application/json",
			Text:     dashboardTooLargeNotice(len(html)),
		}, nil
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
	if !input.Confirmed {
		return "Error: plugin_install requires `confirmed: true`. The MCP host must collect operator consent before forwarding this call. A plugin install runs new code on the operator's machine; auto-approval would be a privilege-escalation vector for prompt injection.", nil
	}
	// Reject obviously suspicious names so a hostile prompt can't tunnel
	// arbitrary args into the subprocess. Plugin names are restricted to
	// the registry's character set.
	if !plugin.IsSafeName(input.Name) {
		return "Error: invalid plugin name (allowed chars: a-z, 0-9, /, -, _, .)", nil
	}
	if input.Version != "" && !plugin.IsSafeVersionConstraint(input.Version) {
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

// fix_plan status values disambiguate the four outcomes an empty actions
// list can represent — see issue #61 (2). An agent reading the response
// can decide whether to act, scan first, or surface a "feature disabled"
// message without guessing.
const (
	fixPlanStatusOKWithActions = "ok_with_actions"
	fixPlanStatusNoVulns       = "no_vulns"
	fixPlanStatusNoDepMetadata = "no_dep_metadata"
)

type fixPlanResponse struct {
	Status       string      `json:"status"`
	Actions      []fixAction `json:"actions"`
	Skipped      int         `json:"skipped"`
	MajorSkipped int         `json:"major_skipped"`
	VulnCount    int         `json:"vuln_count"`
	Note         string      `json:"note,omitempty"`
}

func (s *Server) handleFixPlan(_ context.Context, input fixPlanInput) (mcp.StructuredResult, error) {
	pc := s.getCache("")
	if pc == nil {
		return toolError("no scan results available — run the scan tool first"), nil
	}

	// The plan comes from the SAME core/fix planner the `nox fix` CLI applies,
	// so the actions an agent is shown here are exactly the ones the CLI would
	// run — including the guards against downgrades, prereleases, and
	// unsupported ecosystems that this handler used to lack.
	plan := fix.PlanUpgrades(pc.result.Findings.ActiveFindings(), fix.Options{IncludeMajor: input.IncludeMajor})

	resp := fixPlanResponse{
		Note:         "Plan only. Apply with: nox fix --input findings.json",
		Actions:      []fixAction{},
		Skipped:      plan.Skipped,
		MajorSkipped: plan.MajorSkipped,
		VulnCount:    plan.VulnCount,
	}
	for _, a := range plan.Actions {
		resp.Actions = append(resp.Actions, fixAction{
			RuleID:    a.RuleID,
			Package:   a.Package,
			From:      a.From,
			To:        a.To,
			Ecosystem: a.Ecosystem,
			Command:   a.Command(),
		})
	}

	switch {
	case len(resp.Actions) > 0:
		resp.Status = fixPlanStatusOKWithActions
	case resp.VulnCount == 0:
		resp.Status = fixPlanStatusNoVulns
	default:
		// VULN-001 findings exist but none produced an applicable upgrade
		// (missing metadata, unsupported ecosystem, or held back by a guard).
		resp.Status = fixPlanStatusNoDepMetadata
	}
	return structured(resp)
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
		return ai.RenderMermaid(pc.result.AIInventory), nil
	case "dot":
		return ai.RenderDot(pc.result.AIInventory), nil
	default:
		return "Error: unknown format " + format + " (use mermaid or dot)", nil
	}
}
