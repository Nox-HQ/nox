package bench

import (
	"os"
	"path/filepath"
	"testing"
)

// `nox bench --precision <corpus>` reads its ground truth by walking the corpus
// directory. Through a link that walk saw nothing -- os.Stat follows the link and
// said "directory", WalkDir Lstats it and did not descend -- so a linked corpus
// had zero expectations and zero coverage claims, and every finding scored as a
// false positive once the scan itself stopped being blind to links.

func linkedCorpus(t *testing.T, files map[string]string) (realDir, link string) {
	t.Helper()
	realDir = filepath.Join(t.TempDir(), "corpus")
	for name, body := range files {
		p := filepath.Join(realDir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link = filepath.Join(t.TempDir(), "linked-corpus")
	if err := os.Symlink(realDir, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	return realDir, link
}

func TestParseCorpus_ThroughSymlinkMatchesRealPath(t *testing.T) {
	realDir, link := linkedCorpus(t, map[string]string{
		"py/app.py":  "token = 'x'  # nox-expect: SEC-001\n",
		"go/main.go": "var k = \"x\" // nox-expect: SEC-002, SEC-003\n",
	})
	want, err := ParseCorpus(realDir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseCorpus(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(want) != 3 || len(got) != len(want) {
		t.Fatalf("expectations: %d by the real path, %d through a link", len(want), len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("expectation %d: %+v through a link, %+v by the real path", i, got[i], want[i])
		}
	}
}

func TestParseCoverage_ThroughSymlinkMatchesRealPath(t *testing.T) {
	realDir, link := linkedCorpus(t, map[string]string{
		"a.py": "x = 1  # nox-cover: py-branch-1\n",
	})
	want, err := ParseCoverage(realDir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseCoverage(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(want) != 1 || len(got) != 1 {
		t.Fatalf("claims: %d by the real path, %d through a link", len(want), len(got))
	}
	// The corpus is named as the caller named it: resolving the walk must not
	// rename the corpus to whatever the link points at.
	if got[0].Corpus != "linked-corpus" || got[0].FilePath != want[0].FilePath || got[0].BranchID != want[0].BranchID {
		t.Errorf("claim through a link = %+v; want %+v under corpus %q", got[0], want[0], "linked-corpus")
	}
}
