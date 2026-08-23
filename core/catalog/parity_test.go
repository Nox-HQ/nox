package catalog

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/analyzers/agentflow"
	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/analyzers/data"
	"github.com/nox-hq/nox/core/analyzers/deps"
	"github.com/nox-hq/nox/core/analyzers/fileperms"
	"github.com/nox-hq/nox/core/analyzers/hardening"
	"github.com/nox-hq/nox/core/analyzers/iac"
	"github.com/nox-hq/nox/core/analyzers/memsafe"
	"github.com/nox-hq/nox/core/analyzers/provenance"
	"github.com/nox-hq/nox/core/analyzers/secrets"
	"github.com/nox-hq/nox/core/analyzers/slop"
	"github.com/nox-hq/nox/core/analyzers/taintflow"
	"github.com/nox-hq/nox/core/analyzers/variants"
	"github.com/nox-hq/nox/core/analyzers/weakcrypto"
	"github.com/nox-hq/nox/core/compliance"
	"github.com/nox-hq/nox/core/rules"
)

// This file guards PAIRS OF HAND-MAINTAINED TABLES that must agree.
//
// The failure it exists to prevent has already happened twice in this codebase.
// The lexer knew eight source extensions the file discoverer did not, so those
// files were silently never scanned — a scanner reporting "clean" on code it
// never opened. The MCP summary knew six rule families while the CLI knew
// twenty-one, so whole security categories vanished into an opaque "other"
// bucket for any agent sizing up a scan. Neither drift broke a build; both
// degraded the product silently, which is the only way this class of bug ever
// arrives. Every test below pins one table against the thing it is supposed to
// mirror, so the next divergence is a red test rather than a quiet gap.

// analyzerRuleSets is every built-in analyzer that publishes a RuleSet — the
// ground truth the catalog is supposed to aggregate. It is deliberately spelled
// out rather than derived from allRuleSets(), because allRuleSets() is the very
// table under test: deriving from it would make the guard agree with whatever
// the catalog happens to list. TestAnalyzerInventoryIsComplete cross-checks this
// list against the analyzers directory, so a fifteenth analyzer cannot be added
// without landing here first.
func analyzerRuleSets(t *testing.T) map[string]*rules.RuleSet {
	t.Helper()
	return map[string]*rules.RuleSet{
		// Aggregated by Catalog() today.
		"secrets":    secrets.NewAnalyzer().Rules(),
		"data":       data.NewAnalyzer().Rules(),
		"ai":         ai.NewAnalyzer().Rules(),
		"iac":        iac.NewAnalyzer().Rules(),
		"deps":       deps.NewAnalyzer(deps.WithOSVDisabled()).Rules(),
		"slop":       slop.NewAnalyzer().Rules(),
		"variants":   variants.NewAnalyzer().Rules(),
		"provenance": provenance.NewAnalyzer().Rules(),
		// Publish rules, but are absent from Catalog() — see
		// TestEveryShippedRuleReachesTheCatalog.
		"agentflow":  agentflow.NewAnalyzer().Rules(),
		"fileperms":  fileperms.NewAnalyzer().Rules(),
		"hardening":  hardening.NewAnalyzer().Rules(),
		"memsafe":    memsafe.NewAnalyzer().Rules(),
		"taintflow":  taintflow.NewAnalyzer().Rules(),
		"weakcrypto": weakcrypto.NewAnalyzer().Rules(),
	}
}

// allShippedRules returns every rule every built-in analyzer can emit, keyed by
// rule ID, with the analyzer that owns it.
func allShippedRules(t *testing.T) map[string]string {
	t.Helper()
	owner := make(map[string]string)
	for name, rs := range analyzerRuleSets(t) {
		if rs == nil {
			t.Fatalf("analyzer %s has a nil rule set", name)
		}
		for _, r := range rs.Rules() {
			owner[r.ID] = name
		}
	}
	return owner
}

// TestAnalyzerInventoryIsComplete keeps analyzerRuleSets honest against the
// filesystem. A hand-written list of analyzers is exactly the kind of table that
// rots: someone adds an analyzer, the list is never touched, and every guard
// built on it silently stops covering the new rules. Scanning for the RuleSet
// accessor makes the source tree the authority.
func TestAnalyzerInventoryIsComplete(t *testing.T) {
	const marker = ") Rules() *rules.RuleSet"

	entries, err := os.ReadDir(filepath.Join("..", "analyzers"))
	if err != nil {
		t.Fatalf("reading the analyzers directory: %v", err)
	}

	onDisk := map[string]bool{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join("..", "analyzers", e.Name()))
		if err != nil {
			t.Fatalf("reading analyzer %s: %v", e.Name(), err)
		}
		for _, f := range files {
			if !strings.HasSuffix(f.Name(), ".go") || strings.HasSuffix(f.Name(), "_test.go") {
				continue
			}
			src, err := os.ReadFile(filepath.Join("..", "analyzers", e.Name(), f.Name()))
			if err != nil {
				t.Fatalf("reading %s/%s: %v", e.Name(), f.Name(), err)
			}
			if strings.Contains(string(src), marker) {
				onDisk[e.Name()] = true
				break
			}
		}
	}
	if len(onDisk) == 0 {
		t.Fatal("no analyzer with a RuleSet found on disk; the scan is not exercising anything")
	}

	known := analyzerRuleSets(t)
	for name := range onDisk {
		if _, ok := known[name]; !ok {
			t.Errorf("analyzer %q publishes rules but is missing from analyzerRuleSets; add it there (and to catalog.allRuleSets) so every parity guard covers its rules", name)
		}
	}
	for name := range known {
		if !onDisk[name] {
			t.Errorf("analyzerRuleSets lists %q, which no longer publishes a RuleSet; the entry is dead", name)
		}
	}
}

// TestEveryShippedRuleReachesTheCatalog pins the catalog against the analyzers.
// A rule missing here is invisible to `nox rules`, to the MCP rules tool, and to
// every consumer that joins metadata (remediation, references, severity) by rule
// ID — the finding still fires, but nothing downstream can say what it means.
func TestEveryShippedRuleReachesTheCatalog(t *testing.T) {
	cat := Catalog()
	var missing []string
	for id, owner := range allShippedRules(t) {
		if _, ok := cat[id]; !ok {
			missing = append(missing, id+" ("+owner+")")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d shipped rules are absent from Catalog(): %v", len(missing), missing)
	}
}

// TestNoBuiltinRuleFallsToOther is the test family.go's unknownFamily comment
// already promises by name. Every catalogued rule must land in a real family:
// "other" is not a category, it is the absence of one, and a rule that lands
// there disappears from the MCP summary's by_family map into a bucket an agent
// cannot reason about.
func TestNoBuiltinRuleFallsToOther(t *testing.T) {
	// Deliberately empty. No built-in rule legitimately lacks a family; an entry
	// here would be a documented exception, not a place to park a new prefix.
	allowed := map[string]bool{}

	var orphans []string
	for id := range Catalog() {
		if allowed[id] {
			continue
		}
		if Family(id).Key == "other" {
			orphans = append(orphans, id)
		}
	}
	sort.Strings(orphans)
	if len(orphans) > 0 {
		t.Errorf("%d catalogued rules have no family and collapse to \"other\": %v — add their prefix to familyRules", len(orphans), orphans)
	}
}

// TestEveryShippedRuleHasAFamily extends the guard above past the catalog to
// every rule any analyzer can emit. The two differ today only because the
// catalog is incomplete, and that difference hides the gap: PERM-* and MEMSAFE-*
// have no familyRules entry, so the moment the catalog is fixed they would
// arrive in the "other" bucket rather than being reported as what they are.
func TestEveryShippedRuleHasAFamily(t *testing.T) {
	var orphans []string
	for id, owner := range allShippedRules(t) {
		if Family(id).Key == "other" {
			orphans = append(orphans, id+" ("+owner+")")
		}
	}
	sort.Strings(orphans)
	if len(orphans) > 0 {
		t.Errorf("%d shipped rules have no family: %v", len(orphans), orphans)
	}
}

// TestNoFamilyRuleIsShadowed catches a dead row in familyRules. Family() returns
// the FIRST matching prefix, so a specific prefix listed after a shorter one it
// starts with can never be reached — the entry looks present in the table and
// does nothing, which is how AI-PI-* rules ended up reported as generic AI.
// Labels are checked for uniqueness alongside the keys already guarded in
// family_test.go: two families sharing a label read as one category in the CLI
// summary even when their keys differ.
func TestNoFamilyRuleIsShadowed(t *testing.T) {
	seenLabel := map[string]string{}
	for _, r := range familyRules {
		probe := r.prefix + "000"
		if got := Family(probe).Key; got != r.family.Key {
			t.Errorf("familyRules entry %q is unreachable: Family(%q) = %q, want %q — an earlier, shorter prefix shadows it", r.prefix, probe, got, r.family.Key)
		}
		if prev, dup := seenLabel[r.family.Label]; dup {
			t.Errorf("families %q and %q share the label %q — they read as one category in the summary", prev, r.prefix, r.family.Label)
		}
		seenLabel[r.family.Label] = r.prefix
	}
}

// TestCatalogOWASPTagsBelongToAKnownTaxonomy is the catch-all beside
// TestCatalogLLMTagsAreValid2025, which validates owasp-llm* only. Every other
// owasp-* tag a rule emits — owasp-mcp*, owasp-asi* — must resolve too, and a
// tag from a taxonomy nothing here knows about (or a typo such as "owasp-lmm02")
// must fail rather than travel into SARIF as an unresolvable claim of standards
// alignment.
func TestCatalogOWASPTagsBelongToAKnownTaxonomy(t *testing.T) {
	// The OWASP Agentic Security Initiative list runs ASI01..ASI10. Unlike the
	// LLM and MCP taxonomies, it has no canonical Go table in this repo yet, so
	// the range is the strongest check available — see the report note.
	const asiCategories = 10
	const webTop10Categories = 10

	seen := map[string]int{}
	for id, meta := range Catalog() {
		for _, tag := range meta.Tags {
			if !strings.HasPrefix(tag, "owasp") {
				continue
			}
			seen[tag]++
			switch {
			case strings.HasPrefix(tag, "owasp-llm"):
				// Covered by TestCatalogLLMTagsAreValid2025.
			case strings.HasPrefix(tag, "owasp-mcp"):
				if compliance.ControlForRule("", []string{tag}) == "" {
					t.Errorf("rule %s carries tag %q, which resolves to no OWASP MCP Top 10 control", id, tag)
				}
			case strings.HasPrefix(tag, "owasp-asi"):
				n, err := strconv.Atoi(strings.TrimPrefix(tag, "owasp-asi"))
				if err != nil || n < 1 || n > asiCategories {
					t.Errorf("rule %s carries tag %q, which is not an ASI01..ASI%02d category", id, tag, asiCategories)
				}
			case strings.HasPrefix(tag, "owasp-a"):
				// OWASP Web Top 10 (A01..A10) — a distinct taxonomy from the LLM,
				// MCP and ASI lists above. Matched after them because "owasp-a"
				// is a prefix of "owasp-asi".
				n, err := strconv.Atoi(strings.TrimPrefix(tag, "owasp-a"))
				if err != nil || n < 1 || n > webTop10Categories {
					t.Errorf("rule %s carries tag %q, which is not an A01..A%02d category", id, tag, webTop10Categories)
				}
			default:
				t.Errorf("rule %s carries owasp tag %q from a taxonomy this package does not know; add it to a canonical table before shipping the tag", id, tag)
			}
		}
	}
	for _, want := range []string{"owasp-llm01", "owasp-mcp03", "owasp-asi01"} {
		if seen[want] == 0 {
			t.Errorf("no rule carries %q; this guard is no longer exercising that taxonomy", want)
		}
	}
}

// TestEveryMCPRuleMapsToAnOWASPControl is the other direction of the same pair:
// core/compliance keeps a hand-written MCP-rule -> control table for the rules
// that predate the tags and for the relationally emitted ones. A new MCP-* rule
// that lands with neither a table entry nor an owasp-mcp tag reports no
// standards alignment at all, which is indistinguishable in SARIF from a rule
// that is genuinely out of scope for the framework.
func TestEveryMCPRuleMapsToAnOWASPControl(t *testing.T) {
	checked := 0
	for id, meta := range Catalog() {
		if !strings.HasPrefix(id, "MCP-") {
			continue
		}
		checked++
		control := compliance.ControlForRule(id, meta.Tags)
		if control == "" {
			t.Errorf("rule %s maps to no OWASP MCP control: add it to compliance.mcpRuleControls or tag it owasp-mcpNN", id)
			continue
		}
		if _, ok := compliance.Control(control); !ok {
			t.Errorf("rule %s maps to unknown control %q", id, control)
		}
	}
	if checked == 0 {
		t.Fatal("no MCP-* rules in the catalog; this guard is not exercising anything")
	}
}
