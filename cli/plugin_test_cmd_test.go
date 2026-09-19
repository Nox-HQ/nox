package main

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// buildPluginFixture compiles one of plugin/testdata's fixture plugins.
func buildPluginFixture(t *testing.T, name string) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds a plugin binary; skipped under -short")
	}
	bin := filepath.Join(t.TempDir(), name)
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", bin, "../plugin/testdata/"+name).CombinedOutput(); err != nil {
		t.Fatalf("building %s: %v\n%s", name, err, out)
	}
	return bin
}

// `nox plugin test` used to print "not yet implemented" while being listed in
// `nox plugin`'s usage. It now runs a binary the way a scan will, so its exit
// code has to mean what a scan would do with that plugin.
func TestPluginTestPassesAPluginItsTrackAllows(t *testing.T) {
	bin := buildPluginFixture(t, "authplugin")
	if code := runPluginTest([]string{"--track", "core-analysis", "--target", t.TempDir(), bin}); code != 0 {
		t.Fatalf("a passive, network-free plugin failed under core-analysis: exit %d", code)
	}
}

// The failure that kept nox-plugin-freshness unreleased, caught before
// install: a network host its track does not allow.
func TestPluginTestFailsOnAHostItsTrackForbids(t *testing.T) {
	bin := buildPluginFixture(t, "netplugin")
	if code := runPluginTest([]string{"--track", "core-analysis", "--target", t.TempDir(), bin}); code != 1 {
		t.Fatalf("a plugin declaring proxy.golang.org passed under core-analysis: exit %d, want 1", code)
	}
}

// And the policy fix itself, end to end: supply-chain must admit the Go
// module proxy, the registry freshness audits Go dependencies against.
func TestPluginTestSupplyChainAdmitsTheGoProxy(t *testing.T) {
	bin := buildPluginFixture(t, "netplugin")
	if code := runPluginTest([]string{"--track", "supply-chain", "--target", t.TempDir(), bin}); code != 0 {
		t.Fatalf("supply-chain refused proxy.golang.org: exit %d", code)
	}
}

func TestPluginTestUsageErrors(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir) // no plugin.yaml here, so no track can be inferred
	for name, args := range map[string][]string{
		"no binary":       {"--track", "core-analysis"},
		"missing binary":  {"--track", "core-analysis", filepath.Join(dir, "nope")},
		"unknown track":   {"--track", "no-such-track", "/bin/sh"},
		"no track at all": {"/bin/sh"},
	} {
		if code := runPluginTest(args); code != 2 {
			t.Errorf("%s: exit %d, want 2", name, code)
		}
	}
}

// Routing: `nox plugin test` reaches runPluginTest. With no binary it is a
// usage error, exactly as when the command was a placeholder.
func TestRunPluginTest_ViaPluginCommand(t *testing.T) {
	if code := runPlugin([]string{"test"}); code != 2 {
		t.Fatalf("expected exit code 2 via plugin command, got %d", code)
	}
}
