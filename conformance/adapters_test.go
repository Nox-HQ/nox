// Package conformance holds cross-cutting guards that no single package can
// express: invariants ABOUT the codebase rather than about one unit of it.
//
// It exists because of a specific, repeated failure. nox has three entry points
// over one domain — the CLI, the MCP server, and the LSP — and each is meant to
// be a thin adapter that parses input, calls core, and formats output. Five
// times over, an adapter instead grew its own copy of a domain rule, the copies
// drifted, and the drift dropped a SECURITY signal: the MCP tool showed a
// dependency downgrade the CLI would refuse; the MCP summary collapsed fifteen
// rule families into "other"; the MCP agent-graph lost the capability risk
// colouring entirely. Every one passed its own package's tests, because each
// adapter tested its own copy.
//
// The tests here are the guard that was missing. They assert, structurally,
// that the adapters still route through the shared implementation — so a future
// handler that re-implements a domain rule fails the build instead of quietly
// diverging.
package conformance

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// adapterDirs are the entry-point packages that must stay thin.
var adapterDirs = map[string]string{
	"cli":    "../cli",
	"server": "../server",
}

// sharedOperation is a domain function that more than one adapter must call
// rather than reimplement.
type sharedOperation struct {
	// symbol is the qualified call as it appears in adapter source.
	symbol string
	// adapters are the adapter dirs that must reference it.
	adapters []string
	// why records the drift that made this shared in the first place, so a
	// failure tells the reader what is at stake rather than just what broke.
	why string
}

// sharedOperations is the registry of domain functions the adapters share.
//
// Adding a row here is how a consolidation becomes permanent: from then on, an
// adapter that stops calling the shared function fails this test.
var sharedOperations = []sharedOperation{
	{
		symbol:   "attack.NewPlanView",
		adapters: []string{"cli", "server"},
		why:      "the CLI and the MCP attack_plan tool must project a plan identically, including its PLAUSIBLE status and skip aggregation",
	},
	{
		symbol:   "fix.PlanUpgrades",
		adapters: []string{"cli", "server"},
		why:      "the plan an agent is shown must be exactly what `nox fix` would apply, including the downgrade and prerelease guards the MCP copy once lacked",
	},
	{
		symbol:   "catalog.Family",
		adapters: []string{"cli", "server"},
		why:      "the CLI and MCP summaries must group findings by the same taxonomy; the MCP copy once knew 6 families to the CLI's 21",
	},
	{
		symbol:   "ai.RenderMermaid",
		adapters: []string{"cli", "server"},
		why:      "the agent capability lattice must render identically; the MCP copy once dropped label sanitisation",
	},
	{
		symbol:   "ai.RenderDot",
		adapters: []string{"cli", "server"},
		why:      "the dot lattice must carry the capability RISK colouring; the MCP copy once emitted monochrome nodes, hiding shell_exec-class tools",
	},
	{
		symbol:   "badge.GenerateFromFindings",
		adapters: []string{"cli", "server"},
		why:      "a security grade must not depend on which surface asked for it",
	},
	{
		symbol:   "annotate.BuildReviewPayload",
		adapters: []string{"cli", "server"},
		why:      "PR annotations must be identical whether produced by the CLI or an agent",
	},
	{
		symbol:   "diff.Run",
		adapters: []string{"cli", "server"},
		why:      "changed-file scanning must be one implementation",
	},
}

// TestAdaptersShareDomainImplementations asserts every registered shared
// operation is still called by each adapter that is supposed to call it.
//
// A failure means one of two things, both worth stopping for: the adapter
// dropped the feature, or — the case this exists to catch — it reintroduced a
// local copy of the domain rule.
func TestAdaptersShareDomainImplementations(t *testing.T) {
	sources := map[string]string{}
	for name, dir := range adapterDirs {
		sources[name] = readPackageSource(t, dir)
	}

	for _, op := range sharedOperations {
		t.Run(op.symbol, func(t *testing.T) {
			for _, adapter := range op.adapters {
				src, ok := sources[adapter]
				if !ok {
					t.Fatalf("unknown adapter %q", adapter)
				}
				if !strings.Contains(src, op.symbol) {
					t.Errorf("adapter %q no longer calls %s.\n"+
						"Either the feature was removed, or the adapter reimplemented it locally.\n"+
						"Why this is shared: %s", adapter, op.symbol, op.why)
				}
			}
		})
	}
}

// duplicateNameAllowlist are function names that legitimately appear in more
// than one adapter. Each entry needs a reason: the point of the check is that
// an unexplained duplicate is investigated, not waved through.
var duplicateNameAllowlist = map[string]string{
	"main":      "every binary has one",
	"run":       "generic command-runner naming, not a shared domain rule",
	"newserver": "constructor naming collision, unrelated concerns",
	// Different concerns that happen to share a verb: the CLI's is display
	// truncation for a terminal (takes a width, appends "..."); the server's is
	// MCP transport-budget enforcement (fixed 1MB cap, appends an explicit
	// "output exceeded" notice). Neither is a domain rule.
	"truncate": "cli = terminal display width; server = MCP output-size budget",
}

// TestNoDuplicateHelpersAcrossAdapters flags a function name that exists in more
// than one adapter package.
//
// Every duplication this codebase has suffered announced itself this way first:
// canonicalHash in two packages, renderMermaid beside renderMermaidGraph,
// isSafePluginName beside uriIsSafePluginName. A shared NAME is not proof of
// shared logic, so this is a heuristic — but an unexplained one is worth a look,
// and the allowlist is where "we looked, it is fine" gets recorded.
func TestNoDuplicateHelpersAcrossAdapters(t *testing.T) {
	byAdapter := map[string]map[string]bool{}
	for name, dir := range adapterDirs {
		byAdapter[name] = funcNames(t, dir)
	}

	cliFuncs := byAdapter["cli"]
	serverFuncs := byAdapter["server"]

	for fn := range cliFuncs {
		lower := strings.ToLower(fn)
		if _, ok := duplicateNameAllowlist[lower]; ok {
			continue
		}
		if serverFuncs[fn] {
			t.Errorf("function %q is defined in BOTH cli and server.\n"+
				"If the two implement the same rule, move it into core/ and have both call it.\n"+
				"If they are genuinely unrelated, add %q to duplicateNameAllowlist with a reason.", fn, strings.ToLower(fn))
		}
	}
}

// readPackageSource concatenates every non-test .go file in dir.
func readPackageSource(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	walkGoFiles(t, dir, func(path string, _ []byte) {
		data, err := os.ReadFile(path) //nolint:gosec // repo-relative test input
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		b.Write(data)
		b.WriteByte('\n')
	})
	return b.String()
}

// funcNames returns the top-level function names declared in dir's non-test
// files. Methods are excluded: a method is scoped to its receiver, so the same
// method name on two different types is not duplication.
func funcNames(t *testing.T, dir string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	walkGoFiles(t, dir, func(path string, content []byte) {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, content, parser.SkipObjectResolution)
		if err != nil || file == nil {
			return
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Name == nil {
				continue
			}
			out[fn.Name.Name] = true
		}
	})
	return out
}

// walkGoFiles calls fn for every non-test .go file under dir, skipping
// subdirectories that are their own adapters (cli/lsp, cli/tui) so this compares
// the top-level packages.
func walkGoFiles(t *testing.T, dir string, fn func(path string, content []byte)) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		content, err := os.ReadFile(path) //nolint:gosec // repo-relative test input
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		fn(path, content)
	}
}
