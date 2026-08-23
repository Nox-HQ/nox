package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Flag-efficacy guards for the top-level flags — the ones that apply before a
// subcommand is chosen (--format, --output, --rules, --quiet/-q, --verbose/-v,
// --version).
//
// Two risks live here that the per-subcommand guards do not cover. First, the
// same inert-flag risk as everywhere else: a flag that parses and is never read.
// Second, and specific to this set: ALIAS DRIFT. --quiet and -q are two
// registrations bound to one variable, as are --verbose and -v. If a future edit
// binds a shorthand to its own variable, that shorthand silently stops working
// while both still parse and neither test nor compiler notices.

// topLevelFlagBinding is one registered top-level flag and the variable it binds.
type topLevelFlagBinding struct {
	flag     string
	variable string
}

// topLevelFlagBindings mirrors the registrations in run(). Aliases appear as
// separate rows pointing at the SAME variable, which is what makes the alias
// guard below meaningful.
var topLevelFlagBindings = []topLevelFlagBinding{
	{"format", "formatFlag"},
	{"output", "outputDir"},
	{"rules", "rulesFlag"},
	{"quiet", "quietFlag"},
	{"q", "quietFlag"},
	{"verbose", "verboseFlag"},
	{"v", "verboseFlag"},
	{"version", "versionFlag"},
}

// topLevelAliases are shorthand/long-form pairs that must stay bound to one
// variable.
var topLevelAliases = map[string]string{
	"q": "quiet",
	"v": "verbose",
}

// TestEveryTopLevelFlagIsRead is the inert-flag guard for the top-level set.
func TestEveryTopLevelFlagIsRead(t *testing.T) {
	src := readCLISource(t, "main.go")

	for _, b := range topLevelFlagBindings {
		t.Run(b.flag, func(t *testing.T) {
			// Declaration plus one registration per alias are the baseline uses.
			registrations := strings.Count(src, "&"+b.variable+",")
			uses := strings.Count(src, b.variable)
			if uses <= registrations {
				t.Fatalf("flag --%s: variable %s appears %d times with %d registrations; "+
					"the inventory is stale", b.flag, b.variable, uses, registrations)
			}
			// A variable used only by its declaration and registrations is never
			// consulted, so the flag does nothing.
			if uses <= registrations+1 {
				t.Errorf("flag --%s parses into %s, but nothing reads that variable — "+
					"the flag does nothing", b.flag, b.variable)
			}
		})
	}
}

// TestTopLevelShorthandsBindTheSameVariable guards against alias drift: -q must
// keep setting exactly what --quiet sets.
func TestTopLevelShorthandsBindTheSameVariable(t *testing.T) {
	src := readCLISource(t, "main.go")

	bound := map[string]string{}
	for _, b := range topLevelFlagBindings {
		bound[b.flag] = b.variable
	}

	for short, long := range topLevelAliases {
		sv, okS := bound[short]
		lv, okL := bound[long]
		if !okS || !okL {
			t.Errorf("alias pair -%s/--%s is not fully inventoried", short, long)
			continue
		}
		if sv != lv {
			t.Errorf("-%s binds %s but --%s binds %s; the shorthand no longer sets what the "+
				"long form sets, so one of them silently does nothing", short, sv, long, lv)
		}
		// And the source must actually register both against that variable.
		for _, name := range []string{short, long} {
			if !strings.Contains(src, `&`+sv+`, "`+name+`"`) {
				t.Errorf("flag %q is not registered against %s in main.go", name, sv)
			}
		}
	}
}

// TestTopLevelFlagInventoryMatchesRegistrations diffs the inventory against the
// source both ways, so a new top-level flag cannot appear unguarded.
func TestTopLevelFlagInventoryMatchesRegistrations(t *testing.T) {
	src := readCLISource(t, "main.go")

	registered := map[string]bool{}
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "fs.") || !strings.Contains(trimmed, "Var(&") {
			continue
		}
		open := strings.Index(trimmed, `"`)
		if open < 0 {
			continue
		}
		rest := trimmed[open+1:]
		endQuote := strings.IndexByte(rest, '"')
		if endQuote < 0 {
			continue
		}
		registered[rest[:endQuote]] = true
	}

	inventory := map[string]bool{}
	for _, b := range topLevelFlagBindings {
		inventory[b.flag] = true
	}
	for flag := range registered {
		if !inventory[flag] {
			t.Errorf("top-level flag --%s is registered but not in topLevelFlagBindings; add it "+
				"with the variable it drives so its efficacy is guarded", flag)
		}
	}
	for flag := range inventory {
		if !registered[flag] {
			t.Errorf("topLevelFlagBindings lists --%s, which run() no longer registers", flag)
		}
	}
}

// TestScanOutputFlagRedirectsArtifacts proves --output changes where artifacts
// land rather than merely parsing. A scanner that ignored it would write into
// the scanned repository, which is both surprising and, in CI, a dirty tree.
func TestScanOutputFlagRedirectsArtifacts(t *testing.T) {
	target := t.TempDir()
	writeScanFixture(t, target, "config.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
	out := t.TempDir()

	if code := runScan([]string{target}, "json", out, "", true, false); code > 1 {
		t.Fatalf("scan exited %d", code)
	}
	if _, err := os.Stat(filepath.Join(out, "findings.json")); err != nil {
		t.Fatalf("--output did not redirect findings.json: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "findings.json")); err == nil {
		t.Error("scan wrote findings.json into the SCANNED directory despite --output")
	}
}

// TestScanFormatFlagSelectsArtifacts proves --format decides which artifacts are
// produced. The format flag once lost to config silently (the resolveOutputFormat
// comment records the incident), which turned a gating step into a no-op because
// the file it gated on was never written.
func TestScanFormatFlagSelectsArtifacts(t *testing.T) {
	target := t.TempDir()
	writeScanFixture(t, target, "config.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

	jsonOut := t.TempDir()
	if code := runScan([]string{target}, "json", jsonOut, "", true, false); code > 1 {
		t.Fatalf("json scan exited %d", code)
	}
	if _, err := os.Stat(filepath.Join(jsonOut, "findings.json")); err != nil {
		t.Fatalf("--format json produced no findings.json: %v", err)
	}

	sarifOut := t.TempDir()
	if code := runScan([]string{target}, "sarif", sarifOut, "", true, false); code > 1 {
		t.Fatalf("sarif scan exited %d", code)
	}
	if _, err := os.Stat(filepath.Join(sarifOut, "results.sarif")); err != nil {
		t.Fatalf("--format sarif produced no results.sarif: %v", err)
	}
	// The two formats must actually differ in what they emit, or the flag is
	// decorative.
	if _, err := os.Stat(filepath.Join(sarifOut, "findings.json")); err == nil {
		t.Error("--format sarif also wrote findings.json; the format flag selects nothing")
	}
}
