package core

import (
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/catalog"
)

func TestResolveScopes(t *testing.T) {
	for _, c := range []struct {
		only, skip []string
		ran        []Scope
		full       bool
		err        bool
	}{
		{full: true},
		{only: []string{""}, skip: []string{""}, full: true},
		{only: []string{"secrets"}, ran: []Scope{ScopeSecrets}},
		{only: []string{" Code ", "deps"}, ran: []Scope{ScopeCode, ScopeDeps}},
		{skip: []string{"deps", "supply-chain"}, ran: []Scope{ScopeSecrets, ScopeCode, ScopeIaC, ScopeAI, ScopeData}},
		{only: []string{"code", "deps"}, skip: []string{"deps"}, ran: []Scope{ScopeCode}},
		{only: []string{"secret"}, err: true}, // a typo is an error, not a scan of nothing
		{skip: []string{"everything"}, err: true},
		{only: []string{"code"}, skip: []string{"code"}, err: true}, // nothing left
	} {
		got, err := ResolveScopes(c.only, c.skip)
		if c.err {
			if err == nil {
				t.Errorf("only=%v skip=%v: no error", c.only, c.skip)
			}
			continue
		}
		if err != nil {
			t.Errorf("only=%v skip=%v: %v", c.only, c.skip, err)
			continue
		}
		if got.Full() != c.full {
			t.Errorf("only=%v skip=%v: Full()=%v", c.only, c.skip, got.Full())
		}
		if !c.full && !reflect.DeepEqual(got.Ran(), c.ran) {
			t.Errorf("only=%v skip=%v: ran %v, want %v", c.only, c.skip, got.Ran(), c.ran)
		}
	}
}

// Every analyzer the scan runs has a scope. One missing from analyzerScope
// would run only in full scans, and a scoped scan that should include it would
// silently leave it out.
func TestEveryAnalyzerTaskHasAScope(t *testing.T) {
	src, err := os.ReadFile("scan.go")
	if err != nil {
		t.Fatal(err)
	}
	names := regexp.MustCompile(`(?m)^\t\t\{"([a-z]+)", func\(c context\.Context\) error \{`).FindAllSubmatch(src, -1)
	if len(names) < 14 {
		t.Fatalf("found %d analyzer tasks in scan.go; the pattern no longer matches the task list", len(names))
	}
	for _, m := range names {
		if _, ok := analyzerScope[string(m[1])]; !ok {
			t.Errorf("analyzer %q has no scope in analyzerScope", m[1])
		}
	}
	if len(names) != len(analyzerScope) {
		t.Errorf("scan.go runs %d analyzers, analyzerScope maps %d", len(names), len(analyzerScope))
	}
}

// A scoped scan reports exactly what the full scan reports for that scope:
// the same findings, fingerprints included. And every finding of the full scan
// belongs to some scope, so --only cannot lose a family no scope owns.
func TestScopedScanMatchesFullScanForItsScope(t *testing.T) {
	dirs := []string{"../testdata/precision-suite", "../testdata/precision-corpus", "../testdata/refutation-suite"}
	// NOX_SCOPE_EQUIV_CORPUS adds every repository under a directory (run
	// locally over the benchmark repos, which cover every scope).
	if extra := os.Getenv("NOX_SCOPE_EQUIV_CORPUS"); extra != "" {
		entries, err := os.ReadDir(extra)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.IsDir() {
				dirs = append(dirs, filepath.Join(extra, e.Name()))
			}
		}
	}
	for _, dir := range dirs {
		full, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		owned := map[string]bool{}
		for _, scope := range allScopes {
			set, err := ResolveScopes([]string{string(scope)}, nil)
			if err != nil {
				t.Fatal(err)
			}
			scoped, err := RunScanWithOptions(dir, ScanOptions{Offline: true, Scopes: set})
			if err != nil {
				t.Fatalf("%s --only %s: %v", dir, scope, err)
			}
			patterns := scopeRulePatterns(scope)
			var want []string
			for _, f := range full.Findings.Findings() {
				if matchesAny(f.RuleID, patterns) {
					want = append(want, f.Fingerprint)
					owned[f.Fingerprint] = true
				}
			}
			var got []string
			for _, f := range scoped.Findings.Findings() {
				got = append(got, f.Fingerprint)
			}
			sort.Strings(want)
			sort.Strings(got)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s --only %s: %d findings, the full scan has %d for this scope", dir, scope, len(got), len(want))
			}
		}
		families := map[string]int{}
		for _, f := range full.Findings.Findings() {
			families[strings.SplitN(f.RuleID, "-", 2)[0]]++
		}
		t.Logf("%s: %d findings in the full scan %v", dir, len(full.Findings.Findings()), families)
		if len(full.Findings.Findings()) == 0 {
			t.Errorf("%s: the full scan found nothing, so the equivalence checks nothing", dir)
		}
		for _, f := range full.Findings.Findings() {
			if !owned[f.Fingerprint] {
				t.Errorf("%s: %s (%s) belongs to no scope", dir, f.RuleID, f.Location.FilePath)
			}
		}
	}
}

func matchesAny(id string, patterns []string) bool {
	for _, p := range patterns {
		if ok, _ := path.Match(p, id); ok {
			return true
		}
	}
	return false
}

// A scoped scan says so in findings.json and in SARIF; a full scan's artifacts
// are unchanged (no scope block, no scope notifications).
func TestScopeIsStatedInEveryArtifact(t *testing.T) {
	dir := "../testdata/precision-corpus"
	secretsOnly, err := ResolveScopes([]string{"secrets"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		scopes ScopeSet
		want   bool
	}{{FullScope(), false}, {secretsOnly, true}} {
		res, err := RunScanWithOptions(dir, ScanOptions{Offline: true, Scopes: c.scopes})
		if err != nil {
			t.Fatal(err)
		}
		js, err := res.JSONReporter("test").Generate(res.Findings)
		if err != nil {
			t.Fatal(err)
		}
		hasScope := strings.Contains(string(js), `"scope": {`)
		if hasScope != c.want {
			t.Errorf("full=%v: findings.json scope block present=%v", c.scopes.Full(), hasScope)
		}
		if c.want && !strings.Contains(string(js), `"not_scanned": [`) {
			t.Error("findings.json does not list the scopes that did not run")
		}
		sa, err := res.SARIFReporter("test").Generate(res.Findings)
		if err != nil {
			t.Fatal(err)
		}
		n := strings.Count(string(sa), "nox/scope/not-scanned")
		if want := len(c.scopes.Skipped()); n != want {
			t.Errorf("full=%v: %d SARIF scope notifications, want %d", c.scopes.Full(), n, want)
		}
	}
}

// A scan without the deps scope never reads a lockfile, so it has nothing to
// look up: it must not touch the network even when not offline. Checked on a
// project whose lockfile an offline full scan does read.
func TestAScopeWithoutDepsMakesNoLookups(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests==2.19.0\nflask==0.12\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	full, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Inventory.Packages()) == 0 {
		t.Fatal("test premise: the full scan reads requirements.txt")
	}
	codeOnly, err := ResolveScopes([]string{"code"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := RunScanWithOptions(dir, ScanOptions{Scopes: codeOnly})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(res.Inventory.Packages()); n != 0 {
		t.Errorf("a code-only scan read %d packages", n)
	}
	if len(res.Degradations) != 0 {
		t.Errorf("a code-only scan reported degradations: %+v", res.Degradations)
	}
}

// Every built-in rule belongs to a scope. A rule family no scope claims would
// be reported by a scoped scan of its analyzer yet missing from the scope's
// rule patterns, and skip_analyzer would not remove it.
func TestEveryRuleBelongsToAScope(t *testing.T) {
	var patterns []string
	for _, s := range allScopes {
		patterns = append(patterns, scopeRulePatterns(s)...)
	}
	n := 0
	for _, r := range catalog.Rules() {
		n++
		if !matchesAny(r.ID, patterns) {
			t.Errorf("rule %s belongs to no scope", r.ID)
		}
	}
	if n < 1000 {
		t.Fatalf("checked %d rules; the catalog did not load", n)
	}
}

// A waiver for a rule outside the scan's scopes matched nothing because nothing
// was looked for. Reporting it as unused tells the operator to delete a waiver
// that is still needed, and fails --fail-on-degraded. A waiver for a rule that
// did run is still reported.
func TestScopedScanDoesNotCallOutOfScopeWaiversUnused(t *testing.T) {
	dir := t.TempDir()
	src := "package main\n\n// nox:ignore CRYPTO-001 -- test fixture\nvar a = 1\n\n// nox:ignore SEC-001 -- test fixture\nvar b = 2\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	unused := func(scopes ScopeSet) map[string]bool {
		res, err := RunScanWithOptions(dir, ScanOptions{Offline: true, Scopes: scopes})
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, d := range res.Degradations {
			for _, id := range []string{"CRYPTO-001", "SEC-001"} {
				if strings.Contains(d.Detail, "waives "+id) {
					out[id] = true
				}
			}
		}
		return out
	}
	full := unused(FullScope())
	if !full["CRYPTO-001"] || !full["SEC-001"] {
		t.Fatalf("test premise: the full scan reports both waivers unused, got %v", full)
	}
	secretsOnly, err := ResolveScopes([]string{"secrets"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := unused(secretsOnly)
	if got["CRYPTO-001"] {
		t.Error("a secrets-only scan reported the CRYPTO-001 waiver unused; that rule did not run")
	}
	if !got["SEC-001"] {
		t.Error("a secrets-only scan did not report the unused SEC-001 waiver")
	}
}
