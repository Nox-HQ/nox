// Package taint provides the deterministic, offline foundation for Nox's
// intraprocedural static taint analysis: the typed data model (sources, sinks,
// sanitizers), an embedded per-language catalog, and a pluggable engine
// interface into which the AST/structural dataflow implementation plugs.
//
// WHY a foundation package separate from the dataflow implementation: the full
// source-to-sink propagation depends on an AST/structural substrate that is
// built separately. Freezing the catalog and the lookup contract first lets the
// substrate work land against a stable, tested surface, and lets the catalog be
// reviewed for coverage independently of engine mechanics.
//
// This package is deterministic and offline by construction: the catalog is
// embedded at build time via go:embed, so lookups never touch the network or an
// LLM. The rule IDs and CWEs deliberately mirror the existing
// nox-plugin-taint-analysis (TAINT-001..006, TAINT-AI-001..003) so that findings
// emitted by a future core engine, baselines, and reporters stay consistent with
// the cross-file AI taint plugin already shipping in Nox.
package taint

import (
	"embed"
	"encoding/json"
	"fmt"
	"sync"
)

//go:embed data/catalog.json
var catalogFS embed.FS

// VulnClass is the vulnerability class a sink belongs to. It is the join key
// between a sink and the sanitizers that neutralize it: a sanitizer declares
// which VulnClasses it defuses, and a flow is only reported when a tainted value
// reaches a sink whose VulnClass has not been neutralized on the path.
type VulnClass string

// Vulnerability classes recognized by the taint model. Each maps to a primary
// CWE on the sink definitions and to the vocabulary used by the existing
// taint-analysis plugin.
const (
	VulnCommandInjection      VulnClass = "command_injection"      // CWE-78
	VulnSQLInjection          VulnClass = "sql_injection"          // CWE-89
	VulnCodeInjection         VulnClass = "code_injection"         // CWE-95
	VulnXSS                   VulnClass = "xss"                    // CWE-79
	VulnSSTI                  VulnClass = "ssti"                   // CWE-1336
	VulnPathTraversal         VulnClass = "path_traversal"         // CWE-22
	VulnSSRF                  VulnClass = "ssrf"                   // CWE-918
	VulnUnsafeDeserialization VulnClass = "unsafe_deserialization" // CWE-502
	VulnPromptInjection       VulnClass = "prompt_injection"       // CWE-77 / CWE-200
	VulnOpenRedirect          VulnClass = "open_redirect"          // CWE-601
)

// SourceKind describes the provenance of untrusted input. It is informational
// (it enriches findings and helps triage) rather than part of the taint join;
// any tainted value can in principle reach any sink.
type SourceKind string

// Source provenance kinds. These generalize the kinds already used by
// nox-plugin-taint-analysis (http_query/http_body/http_header/argv/env/stdin)
// with the additional classes called for by the design (file, network,
// deserialized).
const (
	SourceHTTPQuery    SourceKind = "http_query"
	SourceHTTPBody     SourceKind = "http_body"
	SourceHTTPHeader   SourceKind = "http_header"
	SourceArgv         SourceKind = "argv"
	SourceEnv          SourceKind = "env"
	SourceStdin        SourceKind = "stdin"
	SourceFile         SourceKind = "file"
	SourceNetwork      SourceKind = "network"
	SourceDeserialized SourceKind = "deserialized"
)

// Source is a callable (or attribute access) that introduces untrusted data.
type Source struct {
	// Call is the normalized, flattened call/attribute chain, e.g. "os.getenv"
	// or "request.args.get". The engine matches its own normalized call chain
	// against this value.
	Call string `json:"call"`
	// Kind records the provenance for triage and reporting.
	Kind SourceKind `json:"kind"`
}

// Sink is a callable that is dangerous when it receives tainted data. The
// VulnClass drives sanitizer matching; the CWE and RuleID feed finding output.
type Sink struct {
	Call      string    `json:"call"`
	VulnClass VulnClass `json:"vuln_class"`
	CWE       string    `json:"cwe"`
	// RuleID mirrors the existing taint-analysis plugin rule IDs so a core
	// engine's findings coexist with the plugin's under a single ID space.
	RuleID string `json:"rule_id"`
	// Note documents WHY/when the sink is dangerous (e.g. "shell=True"), guiding
	// the future argument-aware refinement in the engine.
	Note string `json:"note,omitempty"`
}

// Sanitizer is a callable that neutralizes taint for one or more VulnClasses.
// A sanitizer is class-specific on purpose: html.escape defuses XSS but does
// nothing for command injection, so neutralization is never global.
type Sanitizer struct {
	Call string `json:"call"`
	// Neutralizes lists the VulnClasses this sanitizer defuses. Membership is
	// the join used by IsSanitizer.
	Neutralizes []VulnClass `json:"neutralizes"`
	Note        string      `json:"note,omitempty"`
}

// languageCatalog is the per-language slice of the catalog as stored in JSON.
type languageCatalog struct {
	Sources    []Source    `json:"sources"`
	Sinks      []Sink      `json:"sinks"`
	Sanitizers []Sanitizer `json:"sanitizers"`
}

// rawCatalog mirrors the on-disk JSON structure for decoding.
type rawCatalog struct {
	SchemaVersion int                        `json:"schema_version"`
	Languages     map[string]languageCatalog `json:"languages"`
}

// Catalog is the loaded, indexed taint catalog. It is safe for concurrent reads
// after construction; all maps are built once and never mutated.
type Catalog struct {
	schemaVersion int
	// Per-language O(1) lookup indexes keyed by normalized call chain.
	sources    map[string]map[string]Source    // lang -> call -> Source
	sinks      map[string]map[string]Sink      // lang -> call -> Sink
	sanitizers map[string]map[string]Sanitizer // lang -> call -> Sanitizer
}

var (
	defaultOnce    sync.Once
	defaultCatalog *Catalog
	defaultErr     error
)

// Default returns the process-wide catalog loaded from the embedded JSON. It is
// lazy-loaded exactly once via sync.Once so repeated callers share the parsed,
// indexed structure without re-reading or re-parsing the embedded file.
func Default() (*Catalog, error) {
	defaultOnce.Do(func() {
		defaultCatalog, defaultErr = load(catalogFS)
	})
	return defaultCatalog, defaultErr
}

// MustDefault is Default without error handling, for callers (and package-level
// initializers) that treat a corrupt embedded catalog as a programming error.
func MustDefault() *Catalog {
	c, err := Default()
	if err != nil {
		panic(fmt.Sprintf("taint: loading embedded catalog: %v", err))
	}
	return c
}

// load parses and indexes the embedded catalog. It is separated from Default so
// tests can exercise parsing/indexing deterministically without the sync.Once.
func load(fsys embed.FS) (*Catalog, error) {
	data, err := fsys.ReadFile("data/catalog.json")
	if err != nil {
		return nil, fmt.Errorf("taint: reading embedded catalog: %w", err)
	}
	var raw rawCatalog
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("taint: parsing embedded catalog: %w", err)
	}
	if len(raw.Languages) == 0 {
		return nil, fmt.Errorf("taint: embedded catalog has no languages")
	}

	c := &Catalog{
		schemaVersion: raw.SchemaVersion,
		sources:       make(map[string]map[string]Source, len(raw.Languages)),
		sinks:         make(map[string]map[string]Sink, len(raw.Languages)),
		sanitizers:    make(map[string]map[string]Sanitizer, len(raw.Languages)),
	}
	for lang, lc := range raw.Languages {
		srcIdx := make(map[string]Source, len(lc.Sources))
		for _, s := range lc.Sources {
			if s.Call == "" {
				return nil, fmt.Errorf("taint: %s: source with empty call", lang)
			}
			srcIdx[s.Call] = s
		}
		sinkIdx := make(map[string]Sink, len(lc.Sinks))
		for _, s := range lc.Sinks {
			if s.Call == "" {
				return nil, fmt.Errorf("taint: %s: sink with empty call", lang)
			}
			if s.VulnClass == "" {
				return nil, fmt.Errorf("taint: %s: sink %q has no vuln_class", lang, s.Call)
			}
			// A later duplicate call for the same language would silently shadow
			// an earlier one; the first definition wins so the catalog is
			// order-stable, matching the plugin's first-match semantics.
			if _, exists := sinkIdx[s.Call]; !exists {
				sinkIdx[s.Call] = s
			}
		}
		sanIdx := make(map[string]Sanitizer, len(lc.Sanitizers))
		for _, s := range lc.Sanitizers {
			if s.Call == "" {
				return nil, fmt.Errorf("taint: %s: sanitizer with empty call", lang)
			}
			sanIdx[s.Call] = s
		}
		c.sources[lang] = srcIdx
		c.sinks[lang] = sinkIdx
		c.sanitizers[lang] = sanIdx
	}
	return c, nil
}

// normalizeLang maps language aliases to their catalog key. TypeScript shares
// the JavaScript catalog because the dangerous call surface is identical.
func normalizeLang(lang string) string {
	switch lang {
	case "ts", "typescript", "tsx", "jsx":
		return "javascript"
	case "js":
		return "javascript"
	case "py":
		return "python"
	case "rb":
		return "ruby"
	default:
		return lang
	}
}

// SchemaVersion reports the catalog schema version, for forward-compatibility
// checks by consumers.
func (c *Catalog) SchemaVersion() int { return c.schemaVersion }

// Languages returns the catalog's canonical language keys (aliases excluded).
func (c *Catalog) Languages() []string {
	langs := make([]string, 0, len(c.sinks))
	for l := range c.sinks {
		langs = append(langs, l)
	}
	return langs
}

// IsSource reports whether call is a known taint source for lang.
func (c *Catalog) IsSource(lang, call string) bool {
	idx, ok := c.sources[normalizeLang(lang)]
	if !ok {
		return false
	}
	_, ok = idx[call]
	return ok
}

// Source returns the Source definition for a call, if any.
func (c *Catalog) Source(lang, call string) (Source, bool) {
	idx, ok := c.sources[normalizeLang(lang)]
	if !ok {
		return Source{}, false
	}
	s, ok := idx[call]
	return s, ok
}

// IsSink reports whether call is a known sink for lang and returns its Sink
// definition (vuln class, CWE, rule ID) when it is.
func (c *Catalog) IsSink(lang, call string) (Sink, bool) {
	idx, ok := c.sinks[normalizeLang(lang)]
	if !ok {
		return Sink{}, false
	}
	s, ok := idx[call]
	return s, ok
}

// IsSanitizer reports whether call neutralizes the given VulnClass for lang.
// Neutralization is class-specific: a sanitizer that defuses XSS returns false
// for command_injection. This is the guard the engine uses to decide whether a
// value that passed through call is still dangerous for a given sink.
func (c *Catalog) IsSanitizer(lang, call string, class VulnClass) bool {
	idx, ok := c.sanitizers[normalizeLang(lang)]
	if !ok {
		return false
	}
	s, ok := idx[call]
	if !ok {
		return false
	}
	for _, vc := range s.Neutralizes {
		if vc == class {
			return true
		}
	}
	return false
}

// Sinks returns all sink definitions for lang. The slice is freshly built and
// may be freely retained by the caller.
func (c *Catalog) Sinks(lang string) []Sink {
	idx := c.sinks[normalizeLang(lang)]
	out := make([]Sink, 0, len(idx))
	for _, s := range idx {
		out = append(out, s)
	}
	return out
}

// Sources returns all source definitions for lang.
func (c *Catalog) Sources(lang string) []Source {
	idx := c.sources[normalizeLang(lang)]
	out := make([]Source, 0, len(idx))
	for _, s := range idx {
		out = append(out, s)
	}
	return out
}

// Sanitizers returns all sanitizer definitions for lang.
func (c *Catalog) Sanitizers(lang string) []Sanitizer {
	idx := c.sanitizers[normalizeLang(lang)]
	out := make([]Sanitizer, 0, len(idx))
	for _, s := range idx {
		out = append(out, s)
	}
	return out
}
