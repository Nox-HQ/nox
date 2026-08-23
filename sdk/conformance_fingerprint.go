package sdk

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

// RunFingerprintStability checks that a plugin's finding fingerprints identify a
// finding in the repository rather than a location on the machine that scanned
// it.
//
// It is the automated form of the reproduction in nox issue #454: seed the same
// content into two directories with different paths, scan both, and compare.
// Any fingerprint that moves is one that cannot be baselined anywhere the
// checkout path differs — every CI runner, every git-worktree pre-push gate,
// any two developers. The symptom appears far from the cause: locally the
// baseline matches and the scan is green, and the gate elsewhere reports
// hundreds of net-new findings for the same commit with nothing in the output
// blaming the path.
//
// seed writes the fixture the plugin should find something in. It is called once
// per directory and must produce byte-identical content both times, or the
// comparison means nothing.
//
// Call this from a plugin's own conformance test:
//
//	func TestConformance(t *testing.T) {
//	    sdk.RunConformance(t, srv)
//	    sdk.RunFingerprintStability(t, srv, writeFixture)
//	}
func RunFingerprintStability(t *testing.T, server pluginv1.PluginServiceServer, seed func(dir string) error) {
	t.Helper()

	client := conformanceClient(t, server)

	manifest, err := client.GetManifest(context.Background(), &pluginv1.GetManifestRequest{ApiVersion: "v1"})
	if err != nil {
		t.Fatalf("GetManifest(v1): %v", err)
	}

	// Two roots that differ in depth and in name length, so a fingerprint that
	// folds in any part of the path moves between them.
	rootA := t.TempDir()
	rootB := filepath.Join(t.TempDir(), "nested", "checkout-with-a-much-longer-name")
	for _, root := range []string{rootA, rootB} {
		if err := ensureDir(root); err != nil {
			t.Fatalf("preparing %s: %v", root, err)
		}
		if err := seed(root); err != nil {
			t.Fatalf("seeding %s: %v", root, err)
		}
	}

	var compared int
	for _, cap := range manifest.GetCapabilities() {
		for _, tool := range cap.GetTools() {
			name := tool.GetName()
			a := scanFingerprints(t, client, name, rootA)
			b := scanFingerprints(t, client, name, rootB)
			if len(a) == 0 || len(b) == 0 {
				continue
			}

			var moved []string
			for key, fpA := range a {
				fpB, ok := b[key]
				if !ok {
					t.Errorf("tool %q reported %s under %s but not under %s; the finding set itself "+
						"depends on the checkout path", name, key, rootA, rootB)
					continue
				}
				compared++
				if fpA != fpB {
					moved = append(moved, key)
				}
			}
			sort.Strings(moved)
			if len(moved) > 0 {
				t.Errorf("tool %q: %d of %d findings changed fingerprint between two checkouts of "+
					"identical content:\n  %s\nA fingerprint must depend on the rule, the "+
					"repo-relative path and the matched content — not on where the repository sits. "+
					"See sdk.Fingerprint.",
					name, len(moved), len(a), strings.Join(moved, "\n  "))
			}
		}
	}

	if compared == 0 {
		t.Fatal("no findings were produced under either root, so nothing was compared. Make seed write " +
			"content this plugin reports on, or the check passes without testing anything")
	}
}

// ensureDir creates dir and any parents.
func ensureDir(dir string) error {
	return os.MkdirAll(dir, 0o750)
}

// scanFingerprints invokes one tool against root and keys each finding by rule
// and repo-relative location, so the two runs can be compared by identity
// rather than by order.
func scanFingerprints(t *testing.T, client pluginv1.PluginServiceClient, tool, root string) map[string]string {
	t.Helper()
	// Both the request field and the conventional input key, since plugins read
	// the workspace root from whichever their SDK generation exposed.
	input, err := structpb.NewStruct(map[string]any{"workspace_root": root})
	if err != nil {
		t.Fatalf("building tool input: %v", err)
	}
	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName:      tool,
		WorkspaceRoot: root,
		Input:         input,
	})
	if err != nil {
		return nil
	}
	out := make(map[string]string, len(resp.GetFindings()))
	for _, f := range resp.GetFindings() {
		loc := f.GetLocation()
		key := fmt.Sprintf("%s %s:%d", f.GetRuleId(),
			RelativePath(root, loc.GetFilePath()), loc.GetStartLine())
		out[key] = f.GetFingerprint()
	}
	return out
}
