package main

import (
	"context"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/plugin"
)

// The heavy path (registering a real plugin binary, gRPC invocation, proto
// conversion) is covered by plugin/host_test.go and plugin/convert_test.go.
// These tests cover this package's orchestration branches.

// With nothing declared, no plugin runs — but the scan must SAY so. Returning a
// silent nil is what let a CI job install a security plugin, get part of its
// coverage, and report a clean scan with nothing to indicate the difference
// (#403). No findings are contributed either way; only the silence changes.
func TestRunScanPlugins_NoRequired_ReportsUndeclaredInstalled(t *testing.T) {
	out, err := runScanPlugins(context.Background(), t.TempDir(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out == nil {
		return // nothing installed on this machine: nothing to report, correctly
	}
	if len(out.Findings) != 0 {
		t.Errorf("no plugin was declared, so none may contribute findings: %+v", out.Findings)
	}
	for _, d := range out.Degradations {
		if strings.Contains(d.Detail, "not listed in plugins.required") {
			return
		}
	}
	t.Errorf("installed-but-undeclared plugins were not reported: %+v", out.Degradations)
}

func TestRunPluginBinaries_NoBinaries_NoOp(t *testing.T) {
	out, err := runPluginBinaries(context.Background(), t.TempDir(), nil, nil, nil, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != nil {
		t.Fatalf("expected nil output for no binaries, got %+v", out)
	}
}

func TestRunScanPlugins_UninstalledRequired_IsReported(t *testing.T) {
	// A required plugin that isn't installed must not abort the scan — but it
	// must not vanish either.
	//
	// This previously asserted a nil output, i.e. that the plugin was silently
	// skipped. That is what let a CI job list a security plugin, fail to
	// install it, and exit 0 with a clean report even under
	// --fail-on-degraded. Skipping is right; staying quiet about it is not.
	out, err := runScanPlugins(context.Background(), t.TempDir(), []string{"nox/definitely-not-installed"})
	if err != nil {
		t.Fatalf("uninstalled required plugin should not abort the scan, got error: %v", err)
	}
	if out == nil {
		t.Fatal("expected a degradation for the uninstalled plugin, got nil output")
	}
	if len(out.Findings) != 0 {
		t.Errorf("expected no findings from an uninstalled plugin, got %d", len(out.Findings))
	}

	var reported bool
	for _, d := range out.Degradations {
		if d.Kind == degrade.Plugin && strings.Contains(d.Detail, "definitely-not-installed") {
			reported = true
		}
	}
	if !reported {
		t.Errorf("the uninstalled required plugin was not reported: %+v", out.Degradations)
	}
}

// The hook must be registered with core at init so `nox scan` runs configured
// analysis plugins without any explicit wiring.
func TestScanPluginHook_Registered(t *testing.T) {
	if core.ScanPluginHook == nil {
		t.Fatal("core.ScanPluginHook was not registered by init()")
	}
}

// TestErrorDegradations_InvocationFailureIsADegradation is the regression test
// for a gate that reported pass while a required check produced nothing.
//
// kraftsport-coach ran `nox scan . -severity-threshold high` as the security
// step of its push gate, with nox/taint-analysis in plugins.required. The
// plugin failed on every invocation. The scan printed one [plugin error] line
// to stderr and reported policy: pass, exit 0 — so the gate passed, for as
// long as the plugin had been broken (#479).
//
// Registration failures already produced a degradation. Invocation failures
// did not, despite having exactly the same consequence: the findings are
// absent either way.
func TestErrorDegradations_InvocationFailureIsADegradation(t *testing.T) {
	diags := []plugin.Diagnostic{
		{Severity: "error", Source: "nox/taint-analysis", Message: "InvokeTool(\"scan\") failed: boom"},
		{Severity: "warn", Source: "nox/sast", Message: "skipped a minified bundle"},
		{Severity: "info", Source: "nox/container", Message: "no Dockerfile"},
	}

	got := errorDegradations(diags, "", "findings are missing")

	if len(got) != 1 {
		t.Fatalf("got %d degradations, want exactly 1 — only the error is a coverage gap: %+v", len(got), got)
	}
	if got[0].Kind != degrade.Plugin {
		t.Errorf("kind = %q, want %q", got[0].Kind, degrade.Plugin)
	}
	if !strings.Contains(got[0].Detail, "nox/taint-analysis") {
		t.Errorf("detail %q does not name the plugin that failed", got[0].Detail)
	}
	if !strings.Contains(got[0].Detail, "boom") {
		t.Errorf("detail %q drops the underlying error", got[0].Detail)
	}
	if got[0].Impact == "" {
		t.Error("a degradation with no impact tells a reader nothing about what is missing")
	}
}

// Warnings must NOT become degradations. A plugin that skipped one file and
// reported it is working as intended; promoting that to a coverage gap would
// make --fail-on-degraded fire constantly and train people to pass it never.
func TestErrorDegradations_NonErrorsAreNotDegradations(t *testing.T) {
	diags := []plugin.Diagnostic{
		{Severity: "warn", Source: "nox/sast", Message: "skipped a vendored file"},
		{Severity: "info", Source: "nox/container", Message: "nothing to do"},
	}
	if got := errorDegradations(diags, "", "irrelevant"); len(got) != 0 {
		t.Fatalf("got %+v, want none — only error severity is a coverage gap", got)
	}
}

// The phase prefix distinguishes the two invocation paths in the output, since
// a missing enrichment and a missing finding are different losses.
func TestErrorDegradations_PhaseIsNamed(t *testing.T) {
	diags := []plugin.Diagnostic{{Severity: "error", Source: "nox/reachability", Message: "boom"}}
	got := errorDegradations(diags, "post-scan ", "enrichments are missing")
	if len(got) != 1 || !strings.Contains(got[0].Detail, "post-scan plugin") {
		t.Fatalf("detail = %+v, want it to name the post-scan phase", got)
	}
}

// Severity comparison is case-insensitive: the string crosses a proto boundary
// and "ERROR" must not silently stop counting as one.
func TestErrorDegradations_SeverityIsCaseInsensitive(t *testing.T) {
	diags := []plugin.Diagnostic{{Severity: "ERROR", Source: "nox/sast", Message: "boom"}}
	if got := errorDegradations(diags, "", "missing"); len(got) != 1 {
		t.Fatalf("got %d, want 1 — severity casing must not decide whether a gap is reported", len(got))
	}
}

// TestRunScanPlugins_VersionConstraint_Resolves covers a required entry
// written with the syntax `nox plugin install` documents and accepts:
//
//	plugins:
//	  required:
//	    - nox/triage-agent@^0.2.0
//
// The lookup used to match the whole string as a name, so such an entry could
// never resolve. nox reported "is not installed" for a plugin that WAS
// installed, and three repositories in one fleet had that plugin silently
// never run because of it.
func TestRunScanPlugins_VersionConstraint_Resolves(t *testing.T) {
	const bare = "nox/triage-agent"
	st, err := LoadState(DefaultStatePath())
	if err != nil || st == nil || st.FindPlugin(bare) == nil {
		t.Skipf("%s is not installed on this machine", bare)
	}

	out, err := runScanPlugins(context.Background(), t.TempDir(), []string{bare + "@^0.2.0"})
	if err != nil {
		t.Fatalf("a constrained required plugin must not abort the scan: %v", err)
	}
	if out == nil {
		return
	}
	for _, d := range out.Degradations {
		if strings.Contains(d.Detail, bare) && strings.Contains(d.Detail, "not installed") {
			t.Errorf("a satisfied constraint was reported as missing: %q", d.Detail)
		}
	}
}

// An UNSATISFIED constraint must still degrade, and must say what is actually
// installed — otherwise the operator cannot tell a typo from a stale install.
func TestRunScanPlugins_VersionConstraint_UnsatisfiedIsReported(t *testing.T) {
	const bare = "nox/triage-agent"
	st, err := LoadState(DefaultStatePath())
	if err != nil || st == nil || st.FindPlugin(bare) == nil {
		t.Skipf("%s is not installed on this machine", bare)
	}

	out, err := runScanPlugins(context.Background(), t.TempDir(), []string{bare + "@^99.0.0"})
	if err != nil {
		t.Fatalf("an unsatisfiable constraint must not abort the scan: %v", err)
	}
	if out == nil {
		t.Fatal("an unsatisfied constraint must be reported, not skipped silently")
	}
	for _, d := range out.Degradations {
		if strings.Contains(d.Detail, "@^99.0.0") {
			if !strings.Contains(d.Detail, st.FindPlugin(bare).Version) {
				t.Errorf("detail %q does not say which version is installed", d.Detail)
			}
			return
		}
	}
	t.Errorf("the unsatisfied constraint was not reported: %+v", out.Degradations)
}
