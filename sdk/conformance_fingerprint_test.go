package sdk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
)

// fakeScanner is a minimal plugin that reports one finding per seeded file. Its
// fingerprint scheme is switchable, so the conformance check can be shown to
// catch the defect rather than merely to pass.
type fakeScanner struct {
	pluginv1.UnimplementedPluginServiceServer
	// pathDependent reproduces the #454 defect: the fingerprint folds in the
	// absolute path, so it moves with the checkout.
	pathDependent bool
}

func (f *fakeScanner) GetManifest(_ context.Context, _ *pluginv1.GetManifestRequest) (*pluginv1.GetManifestResponse, error) {
	return &pluginv1.GetManifestResponse{
		Name: "fake/scanner", Version: "0.1.0", ApiVersion: "v1",
		Capabilities: []*pluginv1.Capability{{
			Tools: []*pluginv1.ToolDef{{Name: "scan"}},
		}},
	}, nil
}

func (f *fakeScanner) InvokeTool(_ context.Context, req *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
	root := req.GetWorkspaceRoot()
	abs := filepath.Join(root, "app.go")
	if _, err := os.Stat(abs); err != nil {
		return &pluginv1.InvokeToolResponse{}, nil
	}
	fp := Fingerprint(root, abs, "FAKE-001", "hardcoded credential")
	if f.pathDependent {
		sum := sha256.Sum256([]byte("FAKE-001|" + abs))
		fp = hex.EncodeToString(sum[:])
	}
	return &pluginv1.InvokeToolResponse{Findings: []*pluginv1.Finding{{
		RuleId:      "FAKE-001",
		Message:     "hardcoded credential",
		Fingerprint: fp,
		Location:    &pluginv1.Location{FilePath: abs, StartLine: 7},
	}}}, nil
}

// seedFixture writes the file the fake scanner reports on.
func seedFixture(dir string) error {
	return os.WriteFile(filepath.Join(dir, "app.go"),
		[]byte("package main\n\nconst token = \"hunter2\"\n"), 0o600)
}

// TestRunFingerprintStabilityPassesAStablePlugin proves the check admits a
// plugin that does the right thing, so a failure below means something.
func TestRunFingerprintStabilityPassesAStablePlugin(t *testing.T) {
	RunFingerprintStability(t, &fakeScanner{}, seedFixture)
}

// TestRunFingerprintStabilityCatchesAPathDependentPlugin is the mutation check,
// written as a test: a plugin fingerprinting on the absolute path must fail,
// and the failure must say so.
func TestRunFingerprintStabilityCatchesAPathDependentPlugin(t *testing.T) {
	// Run the check against each plugin under a throwaway *testing.T and record
	// whether it failed. Both directions are needed: a check that fails on
	// everything catches the defect for the wrong reason, and would still pass
	// a one-sided assertion.
	run := func(pathDependent bool) bool {
		probe := &testing.T{}
		func() {
			defer func() { _ = recover() }()
			RunFingerprintStability(probe, &fakeScanner{pathDependent: pathDependent}, seedFixture)
		}()
		return probe.Failed()
	}

	if !run(true) {
		t.Error("RunFingerprintStability passed a plugin whose fingerprints are derived from the " +
			"absolute path; it would not have caught issue #454")
	}
	if run(false) {
		t.Error("RunFingerprintStability failed a plugin with stable fingerprints, so its failure on " +
			"the broken one proves nothing about fingerprint stability")
	}
}

// TestSDKFingerprintIsPathIndependent pins the helper plugin authors are told to
// use.
func TestSDKFingerprintIsPathIndependent(t *testing.T) {
	// Roots built with the host's own conventions. Hardcoded "/tmp/a" made this
	// vacuous on Windows, where filepath.IsAbs of a slash-rooted path is false:
	// neither path was relativised, so both hashed their full spelling and
	// matched for the wrong reason.
	rootA := filepath.Join(t.TempDir(), "a")
	rootB := filepath.Join(t.TempDir(), "nested", "warden-wt-9f3c2a", "repo")
	fileIn := func(root string, parts ...string) string {
		return filepath.Join(append([]string{root}, parts...)...)
	}

	a := Fingerprint(rootA, fileIn(rootA, "internal", "svc", "handler.go"), "SAST-001", "creds")
	b := Fingerprint(rootB, fileIn(rootB, "internal", "svc", "handler.go"), "SAST-001", "creds")
	if a != b {
		t.Errorf("sdk.Fingerprint moved with the checkout path:\n  %s\n  %s", a, b)
	}

	// It must still distinguish different files, rules and details, or a stable
	// fingerprint would just be a constant.
	if a == Fingerprint(rootA, fileIn(rootA, "internal", "svc", "other.go"), "SAST-001", "creds") {
		t.Error("two different files produced the same fingerprint")
	}
	if a == Fingerprint(rootA, fileIn(rootA, "internal", "svc", "handler.go"), "SAST-002", "creds") {
		t.Error("two different rules produced the same fingerprint")
	}
	if a == Fingerprint(rootA, fileIn(rootA, "internal", "svc", "handler.go"), "SAST-001", "other") {
		t.Error("two different details produced the same fingerprint")
	}
}

// TestSDKRelativePathLeavesUnrelatableInputAlone pins the deliberate
// non-guessing: attributing a finding to the wrong file is worse than an
// unstable fingerprint.
func TestSDKRelativePathLeavesUnrelatableInputAlone(t *testing.T) {
	// Absolute paths built the host's way. Slash-rooted literals are not
	// absolute on Windows, so the earlier version of this test exercised the
	// already-relative branch on that platform and proved nothing about the
	// case it names.
	root := filepath.Join(t.TempDir(), "repo")
	outside := filepath.Join(t.TempDir(), "elsewhere", "lib", "x.go")

	if got := RelativePath(root, outside); got != outside {
		t.Errorf("a path outside the workspace became %q; nox would blame the wrong file", got)
	}
	if got := RelativePath(root, "internal/x.go"); got != "internal/x.go" {
		t.Errorf("an already-relative path became %q", got)
	}
	inside := filepath.Join(root, "internal", "x.go")
	if got := RelativePath("", inside); got != inside {
		t.Errorf("with no root given the path should be untouched, got %q", got)
	}
	// The relatable case, so the three negatives above are not the whole test.
	if got := RelativePath(root, inside); got != "internal/x.go" {
		t.Errorf("a path inside the workspace relativised to %q, want internal/x.go", got)
	}
}
