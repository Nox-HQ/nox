// Package ai implements AI security scanning and inventory extraction. It wraps
// the core/rules engine with built-in rules that detect common AI/LLM security
// risks such as prompt injection boundaries, unsafe MCP tool exposure, insecure
// prompt/response logging, and unpinned models. It also extracts an inventory
// of AI components discovered in the workspace.
package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/nox-hq/nox/core/source"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/reasoning"
	"github.com/nox-hq/nox/core/rules"
)

// Component represents a single AI component discovered in the workspace.
type Component struct {
	// Name is a human-readable identifier for the component.
	Name string `json:"name"`
	// Type classifies the component (e.g., "prompt", "agent", "mcp_config", "model_reference").
	Type string `json:"type"`
	// Path is the file path relative to the workspace root.
	Path string `json:"path"`
	// Details holds additional metadata extracted from the component.
	Details map[string]string `json:"details,omitempty"`
}

// Inventory is the collection of AI components discovered during scanning.
// It is serialised to ai.inventory.json.
type Inventory struct {
	// SchemaVersion identifies the inventory format.
	SchemaVersion string `json:"schema_version"`
	// Components is the list of discovered AI components.
	Components []Component `json:"components"`
	// ConnectionGraph maps connections between AI components.
	ConnectionGraph []Connection `json:"connection_graph,omitempty"`
	// ModelProvenance lists ML model references found in the codebase.
	ModelProvenance []ModelReference `json:"model_provenance,omitempty"`
	// PromptTemplates lists prompt templates discovered in the codebase.
	PromptTemplates []PromptTemplate `json:"prompt_templates,omitempty"`
	// ToolMatrix lists tool permission sets for agents and MCP servers.
	ToolMatrix []ToolPermissionSet `json:"tool_permission_matrix,omitempty"`
}

// NewInventory returns an empty inventory with the current schema version.
func NewInventory() *Inventory {
	return &Inventory{
		SchemaVersion: "2.0.0",
		Components:    []Component{},
	}
}

// Add appends a component to the inventory.
func (inv *Inventory) Add(c Component) {
	inv.Components = append(inv.Components, c)
}

// JSON returns the inventory as pretty-printed JSON bytes.
func (inv *Inventory) JSON() ([]byte, error) {
	return json.MarshalIndent(inv, "", "  ")
}

// WriteFile writes the inventory to the given file path.
func (inv *Inventory) WriteFile(path string) error {
	data, err := inv.JSON()
	if err != nil {
		return fmt.Errorf("marshalling inventory: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}

// Analyzer wraps a rules.Engine pre-loaded with AI security rules and also
// extracts an inventory of AI components.
type Analyzer struct {
	engine *rules.Engine
	// deg collects visible degradations for MCP/agent config parse failures
	// hit while building the tool permission matrix. A nil collector silently
	// discards them (see degrade.Degradations), so tests and library callers
	// that pass no option are unaffected.
	deg *degrade.Degradations
	// reasoning receives a refuting claim for every candidate this analyzer
	// drops. Nil by default and nil for every existing caller; reasoning.Store
	// is nil-safe, so the call sites are unconditional and there is no second
	// code path to drift from the first.
	reasoning *reasoning.Store
}

// RecordReasoningTo directs this analyzer's refutations at store.
func (a *Analyzer) RecordReasoningTo(store *reasoning.Store) { a.reasoning = store }

// refute records why a candidate was dropped, writing the provenance once so
// six call sites cannot spell the producer three different ways.
func (a *Analyzer) refute(subject evidence.Subject, kind evidence.Kind, statement string) {
	a.reasoning.Refute(subject, kind, "nox-scan", "ai", statement)
}

// corroborate records what the analyzer VERIFIED about a candidate it is about
// to report, the positive counterpart of the refiners above.
//
// It exists because of the same gap the secrets analyzer had before E3: every
// drop recorded why it dropped, and every SURVIVOR recorded nothing — so a
// reported AI finding's ledger said only "the rule fired", never what nox
// checked before believing it. A survivor of these refiners has been checked:
// it is in real code, not a comment or blob; an AI-002 interpolation has prompt
// context near it; an AI-006 logging call logs a real value. Recording that is
// what lets `nox why` answer "what supports it" with an inspection rather than
// a tautology.
//
// Every claim here is a heuristic and deliberately so — a proximity check is
// not a proof, and E3 measured that recording these does not move confidence,
// only explanation. Aggregation takes the strongest supporting claim, and three
// heuristics are still a heuristic. What it buys is a ledger that says what was
// examined, not one that would have said only what would have stopped it.
func (a *Analyzer) corroborate(subject evidence.Subject, statement string) {
	a.reasoning.Support(subject, evidence.KindHeuristic, "nox-scan", "ai", statement, nil)
}

// Option configures an Analyzer.
type Option func(*Analyzer)

// WithDegradations wires a degradation collector so config parse failures during
// tool-matrix extraction are surfaced instead of silently defaulting a server to
// "all tools". Without it those failures are invisible.
func WithDegradations(d *degrade.Degradations) Option {
	return func(a *Analyzer) { a.deg = d }
}

// NewAnalyzer creates an Analyzer with built-in AI security rules.
func NewAnalyzer(opts ...Option) *Analyzer {
	rs := rules.NewRuleSet()
	aiRules := builtinAIRules()
	for _, r := range aiRules {
		rs.Add(r)
	}
	a := &Analyzer{
		engine: rules.NewEngine(rs),
	}
	for _, o := range opts {
		o(a)
	}
	return a
}

// Rules returns the analyzer's RuleSet for catalog aggregation.
func (a *Analyzer) Rules() *rules.RuleSet { return a.engine.Rules() }

// ScanFile delegates to the underlying rules engine to scan the given file
// content and returns any AI security findings.
func (a *Analyzer) ScanFile(path string, content []byte) ([]findings.Finding, error) {
	return a.engine.ScanFile(path, content)
}

// suppressNonCode reports whether an AI/MCP pattern finding sits in a comment
// or a data-blob string in lexable source — noise, since such a match is not
// executing code. Returns false for unknown languages (never over-suppress).
func suppressNonCode(lang lexctx.Lang, content []byte, f *findings.Finding) bool {
	if lang == lexctx.LangUnknown {
		return false
	}
	start := lexctx.LineColToOffset(content, f.Location.StartLine, f.Location.StartColumn)
	end := lexctx.LineColToOffset(content, f.Location.EndLine, f.Location.EndColumn)
	if end <= start {
		end = start + 1
	}
	return lexctx.SuppressNonCode(lang, content, start, end)
}

// ScanArtifacts reads each artifact file from disk, scans it for AI security
// issues, and collects findings. It also builds an AI component inventory from
// artifacts classified as AIComponent.
func (a *Analyzer) ScanArtifacts(ctx context.Context, artifacts []discovery.Artifact) (*findings.FindingSet, *Inventory, error) {
	fs := findings.NewFindingSet()
	inv := NewInventory()

	for _, artifact := range artifacts {
		// Honour cancellation between artifacts — see the note in the secrets
		// analyzer: nothing else in this loop consults ctx.
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}

		content, err := os.ReadFile(artifact.AbsPath)
		if err != nil {
			return nil, nil, fmt.Errorf("reading artifact %s: %w", artifact.Path, err)
		}

		// Skip machine-generated / minified blobs: a `.ts` file whose body is
		// a 1.4 MB minified bundle (e.g. vite build output embedded as a string
		// export) is not human-authored AI code, and the path-glob filter can't
		// catch it by name. Content rules (AI-*, MCP-*) only produce noise here;
		// dependency/secrets analyzers run separately and are unaffected.
		if source.IsGenerated(content) {
			continue
		}

		// Scan for AI security rule violations.
		results, err := a.ScanFile(artifact.Path, content)
		if err != nil {
			return nil, nil, fmt.Errorf("scanning artifact %s: %w", artifact.Path, err)
		}
		// Drop matches that land in a comment or a data-blob string in lexable
		// source: an AI/MCP code pattern quoted in a comment or embedded in a
		// base64 blob is not executing code, so it's noise (this is the AI-012
		// -on-changelog-prose false-positive class). Unlike the secrets analyzer,
		// comments are dropped here because a code pattern in a comment is never a
		// real code path.
		lang := lexctx.LangFromPath(artifact.Path)
		for i := range results {
			// Each drop below records WHY before it drops, exactly as the
			// secrets refiners do. The kinds differ and the difference is the
			// point: a lexer region is deterministic, a proximity check is not,
			// and a ledger that called them both the same thing would be
			// asserting more than either established.
			candidate := reasoning.Candidate(results[i].RuleID, artifact.Path,
				results[i].Location.StartLine, results[i].Location.StartColumn)

			if suppressNonCode(lang, content, &results[i]) {
				a.refute(candidate, evidence.KindStatic,
					"the match lies outside code — in a comment, a string literal or an embedded blob")
				continue
			}
			// AI-002 (prompt string concatenation of user input) fires on any
			// interpolated-format-string-plus-user-variable shape, but that shape
			// is just as common in a parameterised SQL call as in a real prompt.
			// Require an actual prompt/LLM context near the match so a
			// parameterised SQL execute call isn't reported as prompt injection.
			if results[i].RuleID == "AI-002" && !hasPromptContext(content, &results[i]) {
				// Heuristic, not static: this is a proximity check over
				// surrounding text, and calling it deterministic would claim
				// the analysis established something it only estimated.
				a.refute(candidate, evidence.KindHeuristic,
					"no prompt or LLM context near the match, so the interpolation is not a prompt")
				continue
			}
			// AI-006 asserts that a prompt or LLM response reaches a log
			// (CWE-532). A call whose arguments are all constant text logs no
			// value at all, so the word "prompt" in its message is a sentence,
			// not a leak — see logsOnlyConstantText.
			if results[i].RuleID == "AI-006" && logsOnlyConstantText(lang, content, &results[i]) {
				a.refute(candidate, evidence.KindStatic,
					"every argument to the logging call is constant text, so the call logs no value and there is no prompt to leak")
				continue
			}
			// AI-049 asserts an eval/code-execution sink (CWE-95). A call
			// executing a SQL statement is a database sink, and the AI token
			// the rule gated on is a column name inside the query text — see
			// isSQLStatementExec.
			if results[i].RuleID == "AI-049" && isSQLStatementExec(content, &results[i]) {
				a.refute(candidate, evidence.KindHeuristic,
					"the call executes a SQL statement, so the AI token the rule gated on is a column name inside the query text")
				continue
			}
			// Survived every refiner above. Record what that means: the match
			// was inspected and is in real code, and for the rules with a
			// context requirement, that the context nox required was present.
			a.corroborate(candidate, "the match was inspected and lies in code, not in a comment, string literal or embedded blob")
			switch results[i].RuleID {
			case "AI-002":
				a.corroborate(candidate, "a prompt or LLM context was found near the interpolation, so it is a prompt rather than an unrelated formatted string")
			case "AI-006":
				a.corroborate(candidate, "the logging call carries a non-constant argument, so it logs a value that could be a prompt or response")
			case "AI-049":
				a.corroborate(candidate, "the call is a code-execution sink rather than a SQL statement whose AI token is a column name")
			}
			fs.Add(results[i])
		}

		// Agent tool-use lattice (OWASP LLM06 Excessive Agency): detect dangerous tool
		// combinations registered in the same source file.
		latticeFindings := scanAgentLattice(artifact.Path, content)
		for i := range latticeFindings {
			fs.Add(latticeFindings[i])
		}

		// Extract inventory entries. AIComponent artifacts (prompts/, agents/,
		// mcp.json, *.prompt) get full extraction. Non-AIComponent source
		// files participate too when their content contains an AI SDK
		// marker — this catches the common case of LLM/embedding calls
		// scattered throughout a polyglot service codebase.
		isAIComp := artifact.Type == discovery.AIComponent
		if isAIComp || (isSourceFile(artifact.Path) && isLikelyAIContent(content)) {
			if isAIComp {
				for _, c := range extractComponents(artifact.Path, content) {
					inv.Add(c)
				}
			}

			inv.ModelProvenance = append(inv.ModelProvenance, extractModelReferences(artifact.Path, content)...)
			inv.PromptTemplates = append(inv.PromptTemplates, extractPromptTemplates(artifact.Path, content)...)
			inv.ToolMatrix = append(inv.ToolMatrix, extractToolPermissions(artifact.Path, content, a.deg)...)

			// Polyglot SDK invocation discovery — captures `client.chat.
			// completions.create(model="gpt-4o")` style call sites that
			// extractModelReferences misses.
			inv.ModelProvenance = append(inv.ModelProvenance, extractSDKInvocations(artifact.Path, content)...)
			for _, comp := range extractFrameworkComponents(artifact.Path, content) {
				inv.Add(comp)
			}
		}
	}

	// Build connection graph from discovered components and tool permissions.
	inv.ConnectionGraph = extractConnections(inv.Components, inv.ToolMatrix)

	fs.Deduplicate()
	return fs, inv, nil
}

// extractComponents inspects the content of an AI component artifact and
// returns inventory entries. It dispatches based on file name and content
// structure.
func extractComponents(path string, content []byte) []Component {
	name := baseName(path)

	switch {
	case name == "mcp.json":
		return extractMCPComponents(path, content)
	case hasSuffix(name, ".prompt") || hasSuffix(name, ".prompt.md"):
		return []Component{{
			Name: name,
			Type: "prompt",
			Path: path,
		}}
	default:
		// Generic AI component (under /agents/ or /prompts/ directory).
		return []Component{{
			Name: name,
			Type: classifyByPath(path),
			Path: path,
		}}
	}
}

// extractMCPComponents parses an mcp.json file and extracts one inventory
// entry per configured MCP server.
func extractMCPComponents(path string, content []byte) []Component {
	// Try to parse as JSON with mcpServers key.
	var config struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}
	if err := json.Unmarshal(content, &config); err != nil {
		// If unparseable, return a single generic entry.
		return []Component{{
			Name: "mcp.json",
			Type: "mcp_config",
			Path: path,
		}}
	}

	if len(config.MCPServers) == 0 {
		return []Component{{
			Name: "mcp.json",
			Type: "mcp_config",
			Path: path,
		}}
	}

	// Sort so the inventory is byte-identical run to run. Map iteration order is
	// randomized, and ai.inventory.json is a reproducible artifact — leaving the
	// order to the map violated the project's determinism guarantee.
	names := make([]string, 0, len(config.MCPServers))
	for serverName := range config.MCPServers {
		names = append(names, serverName)
	}
	sort.Strings(names)

	var components []Component
	for _, serverName := range names {
		components = append(components, Component{
			Name:    serverName,
			Type:    "mcp_server",
			Path:    path,
			Details: map[string]string{"server": serverName},
		})
	}
	return components
}

// classifyByPath returns a component type based on path segments.
func classifyByPath(path string) string {
	if containsSegment(path, "agents") {
		return "agent"
	}
	if containsSegment(path, "prompts") {
		return "prompt"
	}
	return "ai_component"
}

// containsSegment reports whether path contains the given directory segment.
func containsSegment(path, segment string) bool {
	parts := splitPath(path)
	for _, p := range parts {
		if p == segment {
			return true
		}
	}
	return false
}

// splitPath splits a slash-separated path into segments.
func splitPath(path string) []string {
	var parts []string
	for _, p := range split(path, '/') {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

// split splits s by sep and returns the parts.
func split(s string, sep byte) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// baseName returns the last segment of a slash-separated path.
func baseName(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[i+1:]
		}
	}
	return path
}

// hasSuffix reports whether s ends with suffix.
func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
