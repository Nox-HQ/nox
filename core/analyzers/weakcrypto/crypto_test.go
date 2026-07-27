package weakcrypto

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
)

func scanSource(t *testing.T, name, content string) int {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	fs, err := (&Analyzer{}).ScanArtifacts(context.Background(),
		[]discovery.Artifact{{Path: name, AbsPath: p}})
	if err != nil {
		t.Fatal(err)
	}
	return len(fs.Findings())
}

func TestFlagsBrokenPrimitives(t *testing.T) {
	for _, c := range []struct{ name, src string }{
		{"a.go", "package m\nfunc f(){ h := md5.New() ; _ = h }"},
		{"a.go", "package m\nfunc f(){ h := sha1.New() ; _ = h }"},
		{"a.py", "import hashlib\nd = hashlib.md5(b'x')"},
		{"a.js", "const h = crypto.createHash('md5')"},
		{"a.java", "MessageDigest md = MessageDigest.getInstance(\"MD5\");"},
	} {
		if n := scanSource(t, c.name, c.src); n != 1 {
			t.Errorf("%s: got %d findings, want 1 for %q", c.name, n, c.src)
		}
	}
}

func TestIgnoresStrongPrimitives(t *testing.T) {
	for _, c := range []struct{ name, src string }{
		{"a.go", "package m\nfunc f(){ h := sha256.New() ; _ = h }"},
		{"a.py", "import hashlib\nd = hashlib.sha256(b'x')"},
		{"a.js", "const h = crypto.createHash('sha256')"},
	} {
		if n := scanSource(t, c.name, c.src); n != 0 {
			t.Errorf("%s: got %d findings, want 0 for %q", c.name, n, c.src)
		}
	}
}

// The patterns target CONSTRUCTORS, not the algorithm name. Matching prose or
// identifiers would make this rule noisy enough to be globally suppressed,
// which costs more than the rule is worth.
func TestIgnoresMentionsThatAreNotCalls(t *testing.T) {
	for _, c := range []struct{ name, src string }{
		{"a.go", "package m\n// we used to use md5 here, now sha256\nvar md5sum string"},
		{"a.py", "# hashlib.md5 was removed in favour of sha256\nNOTE = 'md5'"},
		{"a.js", "// createHash('md5') is no longer used\nconst algo = 'md5';"},
	} {
		if n := scanSource(t, c.name, c.src); n != 0 {
			t.Errorf("%s: got %d findings, want 0 — matched a mention, not a call: %q", c.name, n, c.src)
		}
	}
}

// Fixtures deliberately exercise weak primitives; flagging them trains people
// to ignore the rule.
func TestSkipsTestFiles(t *testing.T) {
	for _, name := range []string{"a_test.go", "test_a.py", "a.test.js", "a.spec.ts"} {
		src := "md5.New(); hashlib.md5(b''); crypto.createHash('md5')"
		if n := scanSource(t, name, src); n != 0 {
			t.Errorf("%s: got %d findings, want 0 (test file)", name, n)
		}
	}
}

func TestUnknownExtensionIsSkipped(t *testing.T) {
	if n := scanSource(t, "notes.md", "hashlib.md5(b'x')"); n != 0 {
		t.Errorf("got %d findings for a markdown file, want 0", n)
	}
}

func TestRuleIsRegistered(t *testing.T) {
	rs := (&Analyzer{}).Rules().Rules()
	// Two rules: broken primitives (this file) and insecure randomness
	// (rand.go). A rule added without a catalogue entry is invisible to
	// `nox rules`, so the count is asserted rather than only the lookup.
	if len(rs) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rs))
	}
	r, ok := (&Analyzer{}).Rules().ByID(ruleID)
	if !ok {
		t.Fatalf("%s missing from the catalogue", ruleID)
	}
	if r.Metadata["cwe"] != "CWE-327" {
		t.Errorf("cwe = %q, want CWE-327", r.Metadata["cwe"])
	}
}
