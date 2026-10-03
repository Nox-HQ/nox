package discovery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func linkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}

func paths(arts []Artifact) []string {
	out := make([]string, len(arts))
	for i, a := range arts {
		out[i] = a.Path
	}
	return out
}

// A linked root is walked as the directory it names, with the same relative
// paths. Before ResolveRoot it returned no artifacts and no error.
func TestWalk_LinkedRootIsWalked(t *testing.T) {
	realDir := t.TempDir()
	for _, f := range []string{"a.py", "sub/b.tf"} {
		p := filepath.Join(realDir, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(t.TempDir(), "link")
	linkOrSkip(t, realDir, link)

	want, err := NewWalker(realDir).Walk()
	if err != nil {
		t.Fatal(err)
	}
	got, err := NewWalker(link).Walk()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(paths(got), ",") != strings.Join(paths(want), ",") || len(got) != 2 {
		t.Errorf("through link: %v, real path: %v", paths(got), paths(want))
	}
}

// A dangling link is an error. Walking it used to yield an empty tree, which a
// scan reports as clean.
func TestWalk_DanglingRootLinkFails(t *testing.T) {
	link := filepath.Join(t.TempDir(), "dangling")
	linkOrSkip(t, filepath.Join(t.TempDir(), "gone"), link)
	if arts, err := NewWalker(link).Walk(); err == nil {
		t.Fatalf("walking a dangling root link succeeded with %d artifacts; it must fail", len(arts))
	} else if !strings.Contains(err.Error(), "does not resolve") {
		t.Errorf("error = %v, want it to say the link does not resolve", err)
	}
}

// Only the root is resolved. A link inside the tree is still not followed: it
// could leave the project or loop, and that behaviour is unchanged.
func TestWalk_LinksInsideTheTreeAreStillNotFollowed(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.env"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkOrSkip(t, outside, filepath.Join(root, "escape"))

	arts, err := NewWalker(root).Walk()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(paths(arts), ","); got != "main.go" {
		t.Errorf("artifacts = %q; a link inside the tree must not be followed", got)
	}
}

// A root that is not a link comes back exactly as given, so no ordinary scan
// changes.
func TestResolveRoot_LeavesOrdinaryRootsAlone(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{dir, filepath.Join(dir, "missing"), "."} {
		got, err := ResolveRoot(p)
		if err != nil || got != p {
			t.Errorf("ResolveRoot(%q) = %q, %v; want it unchanged", p, got, err)
		}
	}
}
