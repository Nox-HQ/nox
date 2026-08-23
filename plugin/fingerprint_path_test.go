package plugin

import (
	"path/filepath"
	"strings"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

// A baseline matches on fingerprint. If a plugin finding's fingerprint depends
// on where the repository happens to be checked out, the finding cannot be
// baselined anywhere the path is not byte-identical — which is every CI runner,
// every `git worktree` pre-push gate, and any two developers (#454).
//
// The failure is invisible where people look: locally the baseline matches and
// the scan is green, then the same commit reports hundreds of net-new findings
// somewhere else, with nothing in the output attributing the difference to the
// path. It reads as a stale baseline and invites a blanket `baseline update`,
// which accepts those findings unreviewed into a baseline that will not match
// on the next run either.
//
// Plugins commonly report absolute paths — filterPluginFindingsByExclude
// already says so, and relativises them for exclude matching. This pins the
// same normalisation happening before the fingerprint is computed.

// protoFindingAt builds a plugin finding reporting an absolute path under root.
func protoFindingAt(root string) *pluginv1.Finding {
	return &pluginv1.Finding{
		RuleId:   "SAST-001",
		Severity: pluginv1.Severity_SEVERITY_HIGH,
		Message:  "hardcoded credential",
		Location: &pluginv1.Location{
			FilePath:  filepath.Join(root, "internal", "svc", "handler.go"),
			StartLine: 42,
		},
	}
}

// absRoot builds an absolute path with the host's own conventions. Hardcoding
// "/tmp/a" made these guards vacuous on Windows, where filepath.IsAbs of a
// slash-rooted path is false: nothing was relativised, so nothing was tested.
func absRoot(t *testing.T, parts ...string) string {
	t.Helper()
	base := t.TempDir()
	return filepath.Join(append([]string{base}, parts...)...)
}

// TestPluginFingerprintSurvivesADifferentCheckoutPath is the regression guard
// for #454.
func TestPluginFingerprintSurvivesADifferentCheckoutPath(t *testing.T) {
	rootA := absRoot(t, "a")
	rootB := absRoot(t, "nested", "warden-wt-9f3c2a", "repo")

	a := ProtoFindingToGo(protoFindingAt(rootA), "nox/sast", rootA)
	b := ProtoFindingToGo(protoFindingAt(rootB), "nox/sast", rootB)

	if a.Fingerprint != b.Fingerprint {
		t.Errorf("the same finding scanned from two checkouts produced different fingerprints:\n"+
			"  %s at %s\n  %s at %s\n"+
			"a baseline recorded in one cannot match the other, so every plugin finding reappears "+
			"as net-new wherever the path differs", a.Fingerprint, rootA, b.Fingerprint, rootB)
	}
	if a.Fingerprint == "" {
		t.Fatal("no fingerprint was computed; the comparison above is vacuous")
	}
}

// TestPluginFindingPathIsRepoRelative pins the stored location too. A finding
// whose path is absolute is not just unstable — it leaks the scanning machine's
// directory layout into a report that gets uploaded to code scanning, and it
// cannot be matched against a repo-relative baseline entry or suppression.
func TestPluginFindingPathIsRepoRelative(t *testing.T) {
	root := absRoot(t, "work", "repo", "repo")
	f := ProtoFindingToGo(protoFindingAt(root), "nox/sast", root)

	// Slash-separated, matching every other path nox records. Native separators
	// here made a Windows fingerprint differ from a Linux one for the same file.
	want := "internal/svc/handler.go"
	if f.Location.FilePath != want {
		t.Errorf("plugin finding path is %q, want %q — an absolute path cannot match a "+
			"repo-relative baseline entry, exclude pattern or VEX statement",
			f.Location.FilePath, want)
	}
}

// TestPluginFindingPathIsLeftAloneWhenAlreadyRelative guards the other
// direction: a plugin that already reports repo-relative paths must not have
// them mangled.
func TestPluginFindingPathIsLeftAloneWhenAlreadyRelative(t *testing.T) {
	pf := &pluginv1.Finding{
		RuleId:   "SAST-001",
		Message:  "hardcoded credential",
		Location: &pluginv1.Location{FilePath: "internal/svc/handler.go", StartLine: 42},
	}
	root := absRoot(t, "a")
	f := ProtoFindingToGo(pf, "nox/sast", root)
	if f.Location.FilePath != "internal/svc/handler.go" {
		t.Errorf("an already-relative plugin path became %q", f.Location.FilePath)
	}

	// And it must fingerprint identically to the absolute form of the same file,
	// or the two reporting styles produce two baseline entries for one finding.
	abs := ProtoFindingToGo(protoFindingAt(root), "nox/sast", root)
	if f.Fingerprint != abs.Fingerprint {
		t.Error("a plugin reporting a relative path and one reporting the absolute path for the same " +
			"file produced different fingerprints")
	}
}

// TestPluginFindingPathIsSlashSeparated pins the separator convention.
//
// Every path nox records is slash-separated. A plugin finding that kept native
// separators produced `internal\svc\handler.go` on Windows where a core finding
// produced `internal/svc/handler.go`, which meant the fingerprint for one file
// in one repository differed between a Windows developer and Linux CI — the
// #454 defect again, across operating systems rather than across directories —
// and left forward-slash exclude patterns unable to match plugin paths at all.
//
// On POSIX this holds trivially. It is written for the Windows job, which is
// where the two conventions diverge and where the original slip was caught.
func TestPluginFindingPathIsSlashSeparated(t *testing.T) {
	root := absRoot(t, "repo")
	f := ProtoFindingToGo(protoFindingAt(root), "nox/sast", root)

	if strings.ContainsRune(f.Location.FilePath, '\\') {
		t.Errorf("plugin finding path %q contains a backslash; every other path nox records is "+
			"slash-separated, so this file fingerprints differently on Windows than on Linux",
			f.Location.FilePath)
	}
	if !strings.Contains(f.Location.FilePath, "/") {
		t.Fatalf("path %q has no separator at all; the assertion above cannot have tested anything",
			f.Location.FilePath)
	}
}

// TestPluginAndSDKAgreeOnRepoRelativePaths keeps the host and the plugin SDK
// from drifting apart. They are two halves of one contract: the SDK is what
// plugin authors are told to use, the host is what runs on whatever the plugin
// actually sent. When these disagreed, the disagreement showed up as an
// unbaselineable finding rather than as an error.
func TestPluginAndSDKAgreeOnRepoRelativePaths(t *testing.T) {
	root := absRoot(t, "repo")
	abs := filepath.Join(root, "internal", "svc", "handler.go")

	host := repoRelativePath(abs, root)
	author := sdk.RelativePath(root, abs)
	if host != author {
		t.Errorf("host relativised %q to %q, the SDK to %q — a plugin doing exactly what it was "+
			"told still produces a path the host disagrees with", abs, host, author)
	}
}
