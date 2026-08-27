package main

import (
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/types/known/structpb"
)

// A plugin walks the workspace itself, so the exclusions the operator wrote
// only reach it if the host sends them. Issue #455: nox/sast aborted its whole
// scan on a minified bundle under node_modules, and adding the path to
// scan.exclude did not help because the plugin never saw the patterns. SAST
// coverage was therefore silently absent on any machine with dependencies
// installed, and present in CI — so a baseline built where the plugin had never
// run rejected a push where it had.
//
// The host still drops findings under excluded paths after the fact, but
// post-filtering cannot stop a plugin walking into a directory it should never
// have entered.

// TestScanExcludePatternsReachThePluginInput pins the patterns being read from
// the operator's config.
func TestScanExcludePatternsReachThePluginInput(t *testing.T) {
	dir := t.TempDir()
	const config = `scan:
  exclude:
    - "web/node_modules/**"
    - "dist/"
`
	if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte(config), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	got := scanExcludePatterns(dir)
	if len(got) != 2 {
		t.Fatalf("read %v from scan.exclude, want two patterns — a plugin that walks the tree "+
			"cannot honour exclusions it is never told about", got)
	}
	if got[0] != "web/node_modules/**" || got[1] != "dist/" {
		t.Errorf("read %v, want the patterns as written", got)
	}
}

// TestScanExcludePatternsSurviveAMissingConfig pins the deliberate choice not to
// fail here. Refusing to run the plugins because a config is absent or broken
// would turn a config warning into lost coverage — the exact trade #455 is about.
func TestScanExcludePatternsSurviveAMissingConfig(t *testing.T) {
	if got := scanExcludePatterns(t.TempDir()); got != nil {
		t.Errorf("a workspace with no .nox.yaml yielded %v, want none", got)
	}

	broken := t.TempDir()
	if err := os.WriteFile(filepath.Join(broken, ".nox.yaml"), []byte("scan: [this is not\n"), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	if got := scanExcludePatterns(broken); got != nil {
		t.Errorf("an unparsable .nox.yaml yielded %v, want none", got)
	}
}

// TestPluginScanInputCarriesTheExclusions is the wiring guard. Proving the
// patterns can be READ says nothing about them being SENT, and "read but never
// sent" is exactly what #455 was.
func TestPluginScanInputCarriesTheExclusions(t *testing.T) {
	dir := t.TempDir()
	const config = "scan:\n  exclude:\n    - \"web/node_modules/**\"\n"
	if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte(config), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	input := pluginScanInput(dir, dir)
	if input["workspace_root"] != dir {
		t.Errorf("workspace_root = %v, want %s", input["workspace_root"], dir)
	}
	// []any, not []string. This assertion used to read []string, which is the
	// type the code produced and the one type that cannot survive the trip:
	// the input crosses to the plugin as a structpb.Struct, and
	// structpb.NewStruct rejects []string. Because it converts the whole map
	// or none of it, the wrong type here did not drop the exclusions — it
	// failed the InvokeTool request outright, so every scan-tool plugin in a
	// workspace with scan.exclude never ran at all.
	//
	// The test still passed throughout. It proved the patterns were READ and
	// PLACED IN THE MAP, which is what #455 was about, and stopped one step
	// short of the thing that actually carries them.
	excl, ok := input["exclude"].([]any)
	if !ok {
		t.Fatalf("the plugin input carries no exclude patterns (%T); a plugin walking the tree "+
			"cannot honour exclusions it is never sent", input["exclude"])
	}
	if len(excl) != 1 || excl[0] != "web/node_modules/**" {
		t.Errorf("plugin input exclude = %v, want the configured pattern", excl)
	}
}

// TestPluginScanInputConvertsToStructpb is the assertion the wiring guard above
// was missing. "Read but never sent" was #455; this is "sent but never
// convertible", which looks identical from inside the process and identical in
// the scan output — the invocation error is a diagnostic, and the scan still
// reports pass and exits 0.
//
// Asserting on the conversion rather than the Go type is the point. []string
// reads as entirely reasonable; only structpb disagrees, so only structpb can
// be trusted to notice.
func TestPluginScanInputConvertsToStructpb(t *testing.T) {
	dir := t.TempDir()
	const config = "scan:\n  exclude:\n    - \"**/go.sum\"\n    - \"web/pnpm-lock.yaml\"\n"
	if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte(config), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	if _, err := structpb.NewStruct(pluginScanInput(dir, dir)); err != nil {
		t.Fatalf("the plugin input must convert to structpb, got %v — a plugin that cannot be "+
			"sent its input never runs, and the scan reports pass regardless", err)
	}
}

// TestPluginScanInputOmitsAnEmptyExclude keeps the input clean when there is
// nothing to say, so a plugin cannot mistake an empty list for "exclude
// everything".
func TestPluginScanInputOmitsAnEmptyExclude(t *testing.T) {
	input := pluginScanInput(t.TempDir(), "/abs")
	if _, present := input["exclude"]; present {
		t.Error("an exclude key was sent for a workspace that configures none")
	}
}
