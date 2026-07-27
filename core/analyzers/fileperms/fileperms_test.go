package fileperms

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
)

// scanGo runs the analyzer over a single named source file and returns its
// findings. It goes through ScanArtifacts rather than scanSource so the path
// filtering (extension, test trees) is exercised too.
func scanGo(t *testing.T, name, src string) []findings.Finding {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, filepath.Base(name))
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	fs, err := (&Analyzer{}).ScanArtifacts(context.Background(),
		[]discovery.Artifact{{Path: name, AbsPath: p}})
	if err != nil {
		t.Fatal(err)
	}
	return fs.Findings()
}

// body wraps statements in a compilable file so fixtures stay readable.
func body(stmts string) string {
	return "package m\n\nimport (\n\t\"io/fs\"\n\t\"os\"\n)\n\nvar _ = fs.ModeSticky\n\nfunc f(p string, b []byte) {\n" + stmts + "\n}\n"
}

func TestFlagsWorldWritableFiles(t *testing.T) {
	for _, c := range []struct{ name, stmt, wantMode string }{
		{"WriteFile 0666", `_ = os.WriteFile(p, b, 0666)`, "0666"},
		{"WriteFile 0o777", `_ = os.WriteFile(p, b, 0o777)`, "0777"},
		{"WriteFile 0646", `_ = os.WriteFile(p, b, 0646)`, "0646"},
		{"Chmod 0777", `_ = os.Chmod(p, 0777)`, "0777"},
		{"Chmod FileMode conversion", `_ = os.Chmod(p, os.FileMode(0777))`, "0777"},
		{"Chmod fs.FileMode conversion", `_ = os.Chmod(p, fs.FileMode(0o666))`, "0666"},
		{"OpenFile 0666", `_, _ = os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0666)`, "0666"},
		{"underscored literal", `_ = os.Chmod(p, 0o7_77)`, "0777"},
		// A decimal literal is not a typo to forgive: 666 decimal IS 0o1232,
		// which really does carry the world-write bit.
		{"decimal literal", `_ = os.Chmod(p, 666)`, "01232"},
	} {
		got := scanGo(t, "a.go", body(c.stmt))
		if len(got) != 1 {
			t.Errorf("%s: got %d findings, want 1 for %q", c.name, len(got), c.stmt)
			continue
		}
		if got[0].RuleID != ruleFile {
			t.Errorf("%s: rule = %s, want %s", c.name, got[0].RuleID, ruleFile)
		}
		if got[0].Metadata["mode"] != c.wantMode {
			t.Errorf("%s: mode = %q, want %q", c.name, got[0].Metadata["mode"], c.wantMode)
		}
	}
}

func TestFlagsWorldWritableDirectories(t *testing.T) {
	for _, c := range []struct{ name, stmt string }{
		{"MkdirAll 0777", `_ = os.MkdirAll(p, 0777)`},
		{"MkdirAll 0o777", `_ = os.MkdirAll(p, 0o777)`},
		{"Mkdir 0777", `_ = os.Mkdir(p, 0777)`},
		// 0o1777 does NOT set Go's ModeSticky (os.Mkdir masks the numeric mode
		// with Perm(), 0o777, and reads sticky only from ModeSticky), so this is
		// a world-writable directory with no sticky protection.
		{"raw 1777 is not sticky", `_ = os.Mkdir(p, 0o1777)`},
	} {
		got := scanGo(t, "a.go", body(c.stmt))
		if len(got) != 1 {
			t.Errorf("%s: got %d findings, want 1 for %q", c.name, len(got), c.stmt)
			continue
		}
		if got[0].RuleID != ruleDir {
			t.Errorf("%s: rule = %s, want %s", c.name, got[0].RuleID, ruleDir)
		}
	}
}

// The threshold is the world-write bit, and nothing else. 0644 and 0755 are the
// idiomatic Go defaults; reporting them is how a permission rule earns a
// project-wide suppression.
func TestIgnoresNonWorldWritableModes(t *testing.T) {
	for _, stmt := range []string{
		`_ = os.WriteFile(p, b, 0600)`,
		`_ = os.WriteFile(p, b, 0644)`,
		`_ = os.WriteFile(p, b, 0o644)`,
		`_ = os.Chmod(p, 0755)`,
		`_ = os.Chmod(p, 0640)`,
		`_ = os.MkdirAll(p, 0750)`,
		`_ = os.MkdirAll(p, 0755)`,
		`_ = os.Mkdir(p, 0700)`,
		`_, _ = os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0600)`,
		// Group-writable is a deliberate shared-service pattern, not a defect.
		`_ = os.WriteFile(p, b, 0660)`,
		`_ = os.Chmod(p, os.FileMode(0644))`,
	} {
		if got := scanGo(t, "a.go", body(stmt)); len(got) != 0 {
			t.Errorf("got %d findings, want 0 for %q: %+v", len(got), stmt, got)
		}
	}
}

// A world-writable directory with the sticky bit is the /tmp model: anyone may
// create entries, only an entry's owner may remove them. That is a design, not
// an oversight.
func TestStickyDirectoryIsNotFlagged(t *testing.T) {
	for _, stmt := range []string{
		`_ = os.MkdirAll(p, 0777|os.ModeSticky)`,
		`_ = os.MkdirAll(p, os.ModeSticky|0o777)`,
		`_ = os.Mkdir(p, os.FileMode(0777)|os.ModeSticky)`,
		`_ = os.MkdirAll(p, fs.ModeSticky|0777)`,
	} {
		if got := scanGo(t, "a.go", body(stmt)); len(got) != 0 {
			t.Errorf("got %d findings, want 0 for sticky %q: %+v", len(got), stmt, got)
		}
	}
}

// Structural matching is the entire reason this analyzer parses instead of
// grepping: a permission literal in prose or in a string is not a call.
func TestIgnoresLiteralsThatAreNotModes(t *testing.T) {
	for _, name := range []string{"comment", "string", "unrelated"} {
		var stmt string
		switch name {
		case "comment":
			stmt = "\t// historically this was os.MkdirAll(p, 0777)\n\t_ = os.MkdirAll(p, 0755)"
		case "string":
			stmt = "\t_ = os.WriteFile(p, []byte(\"chmod 0777 /srv\"), 0600)\n\tconst doc = \"os.Chmod(p, 0777)\"\n\t_ = doc"
		case "unrelated":
			// Not a mode argument at all: an exit code, a bitmask, a wrapper
			// with a different signature, and a method on a value.
			stmt = "\tconst mask = 0777\n\t_ = mask\n\t_ = os.Chtimes\n\t_ = write(p, b, 0777)"
		}
		if got := scanGo(t, "a.go", body(stmt)+"\nfunc write(string, []byte, int) error { return nil }\n"); len(got) != 0 {
			t.Errorf("%s: got %d findings, want 0: %+v", name, len(got), got)
		}
	}
}

// The mode must be pinned down in the call. A named constant needs go/types to
// resolve, and guessing is the wrong failure direction for a rule like this.
func TestUnresolvableModeIsNotFlagged(t *testing.T) {
	for _, stmt := range []string{
		`_ = os.MkdirAll(p, dirPerm)`,
		`_ = os.Chmod(p, modeFor(p))`,
		// &^ clears bits, so the result cannot be read off the left operand.
		`_ = os.Chmod(p, 0777&^0o022)`,
	} {
		src := body(stmt) + "\nconst dirPerm = 0o777\n\nfunc modeFor(string) os.FileMode { return 0o777 }\n"
		if got := scanGo(t, "a.go", src); len(got) != 0 {
			t.Errorf("got %d findings, want 0 for %q: %+v", len(got), stmt, got)
		}
	}
}

// An OR against an opaque operand is still conclusive when the literal half
// already sets world-write: OR only ever adds bits.
func TestOrWithOpaqueOperandStillFlags(t *testing.T) {
	src := body(`_ = os.Chmod(p, 0666|extra)`) + "\nvar extra os.FileMode\n"
	if got := scanGo(t, "a.go", src); len(got) != 1 {
		t.Errorf("got %d findings, want 1: %+v", len(got), got)
	}
}

// The tar-extraction idiom clamps an archive entry's mode and forces a floor.
// Both lines are real code from registry/oci/extract.go; flagging a hardening
// idiom is precisely how a permission rule earns a repo-wide suppression.
func TestArchiveModeClampIdiomIsNotFlagged(t *testing.T) {
	src := "package m\n\nimport \"os\"\n\nfunc f(target, tmp string, hdrMode int64, mode os.FileMode) {\n" +
		"\t_ = os.MkdirAll(target, os.FileMode(hdrMode)&0o777|0o755)\n" +
		"\t_, _ = os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode&0o777|0o644)\n}\n"
	if got := scanGo(t, "a.go", src); len(got) != 0 {
		t.Errorf("got %d findings, want 0: %+v", len(got), got)
	}
}

// Arity is checked exactly so a project's own helper cannot be read as the
// stdlib call with the mode in a different position.
func TestWrongArityIsNotFlagged(t *testing.T) {
	src := "package m\n\ntype pkg struct{}\n\nfunc (pkg) WriteFile(a string, b []byte, c, d int) error { return nil }\n\nvar os pkg\n\nfunc f() { _ = os.WriteFile(\"p\", nil, 0777, 0) }\n"
	if got := scanGo(t, "a.go", src); len(got) != 0 {
		t.Errorf("got %d findings, want 0: %+v", len(got), got)
	}
}

// Test trees are where deliberate 0777 lives, this analyzer's own fixtures
// included. Flagging them trains people to ignore the rule.
func TestSkipsTestAndFixtureTrees(t *testing.T) {
	for _, name := range []string{"a_test.go", "testdata/a.go", "core/testdata/x/a.go"} {
		if got := scanGo(t, name, body(`_ = os.MkdirAll(p, 0777)`)); len(got) != 0 {
			t.Errorf("%s: got %d findings, want 0", name, len(got))
		}
	}
}

func TestNonGoFileIsSkipped(t *testing.T) {
	if got := scanGo(t, "notes.md", "os.MkdirAll(p, 0777)"); len(got) != 0 {
		t.Errorf("got %d findings for markdown, want 0", len(got))
	}
}

// A file that does not compile must degrade to fewer findings, never panic.
func TestUnparseableSourceDoesNotPanic(t *testing.T) {
	scanGo(t, "a.go", "package m\nfunc f( { os.Chmod(p, 0777) }")
}

func TestReportsTheModeArgumentLine(t *testing.T) {
	src := "package m\n\nimport \"os\"\n\nfunc f(p string) {\n\t_ = os.Chmod(\n\t\tp,\n\t\t0777,\n\t)\n}\n"
	got := scanGo(t, "a.go", src)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Location.StartLine != 8 {
		t.Errorf("line = %d, want 8 (the mode argument)", got[0].Location.StartLine)
	}
	if !strings.Contains(got[0].Message, "os.Chmod") || !strings.Contains(got[0].Message, "0777") {
		t.Errorf("message = %q, want it to name the call and the mode", got[0].Message)
	}
}

func TestRulesAreRegistered(t *testing.T) {
	rs := (&Analyzer{}).Rules().Rules()
	if len(rs) != 2 {
		t.Fatalf("got %d rules, want 2: %+v", len(rs), rs)
	}
	seen := map[string]bool{}
	for _, r := range rs {
		seen[r.ID] = true
		if r.Metadata["cwe"] != "CWE-732" {
			t.Errorf("%s: cwe = %q, want CWE-732", r.ID, r.Metadata["cwe"])
		}
		if r.Severity != findings.SeverityMedium || r.Confidence != findings.ConfidenceHigh {
			t.Errorf("%s: severity/confidence = %s/%s, want medium/high", r.ID, r.Severity, r.Confidence)
		}
	}
	if !seen[ruleFile] || !seen[ruleDir] {
		t.Errorf("missing rule IDs: %+v", seen)
	}
}
