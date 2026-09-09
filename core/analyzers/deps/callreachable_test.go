package deps

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/applicability"
	"github.com/nox-hq/nox/core/callgraph"
	"github.com/nox-hq/nox/core/capability"
)

// goModule writes a buildable Go module and returns its root.
func goModule(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	return dir
}

// Milestone 7.3's exit, first half: a dependency CVE demonstrated genuinely
// impacting, with the evidence that makes it so.
//
// `go list -deps` establishes that the build LINKS the affected package —
// applicability.SymbolUsed, and as far as the ladder could climb before
// core/callgraph existed. The graph answers the next rung: which of this
// module's functions reach for the package, and whether execution gets to them.
//
// The witness is the real chain of calls, so a reader can follow it rather than
// take the rung on trust.
func TestACVEInCalledCodeClimbsToCallReachable(t *testing.T) {
	dir := goModule(t, map[string]string{
		"go.mod": "module example.com/app\n\ngo 1.21\n",
		"main.go": `package main

import "crypto/md5"

func digest(b []byte) [16]byte { return md5.Sum(b) }

func main() { digest([]byte("x")) }
`,
	})
	g := callgraph.BuildGo(dir)

	path, ok := goCallReachable(g, dir, []string{"crypto/md5"})
	if !ok {
		t.Fatal("no call path found to a package main demonstrably calls")
	}
	if len(path) < 2 {
		t.Errorf("path = %v, want a chain from main through digest", path)
	}
	if path[0] != "main" {
		t.Errorf("the witness does not start at a concrete entry point: %v", path)
	}

	v := applicability.Established(applicability.CallReachable, path)
	if v.Outcome != applicability.Impacting {
		t.Errorf("outcome = %q, want impacting", v.Outcome)
	}
	// The sentence must not read as "exploitable". A path existing is not an
	// attacker being able to take it.
	desc := v.Describe()
	if !strings.Contains(desc, "not that an attacker can take it") {
		t.Errorf("the verdict reads as stronger than it is: %q", desc)
	}
}

// The second half: present, and demonstrably NOT impacting, with scope-sound
// evidence rather than an absence.
//
// The module requires the affected package and imports only the standard
// library, so `go list -deps` enumerates the whole closure and the affected
// import is genuinely not in it. That is a universal claim this analysis can
// actually make — the toolchain saw everything — which is why it may refute
// where the call graph may not.
func TestACVEInAnUnlinkedPackageIsNotImpacting(t *testing.T) {
	dir := goModule(t, map[string]string{
		"go.mod": "module example.com/app\n\ngo 1.21\n\nrequire golang.org/x/text v0.3.7\n",
		"main.go": `package main

import "crypto/sha256"

func main() { sha256.Sum256([]byte("x")) }
`,
	})
	linked, known := goImportedPackages(t.Context(), dir)
	if !known {
		t.Skip("the toolchain could not enumerate this module")
	}

	r, ok := goSymbolReferenced([]string{"golang.org/x/text/language"}, linked, known)
	if !ok {
		t.Fatalf("expected a conclusive answer, got %s", r.Outcome)
	}
	v := applicability.Refuted(applicability.AffectedVersion, applicability.SymbolUsed,
		capability.Negative, []string{r.Because})
	if v.Outcome != applicability.NotImpacting {
		t.Fatalf("outcome = %q, want not_impacting", v.Outcome)
	}
	desc := v.Describe()
	if strings.Contains(strings.ToLower(desc), "safe") {
		t.Errorf("the verdict says safe: %q", desc)
	}
	if !strings.Contains(desc, "not linked by this build") {
		t.Errorf("the verdict does not say what was established: %q", desc)
	}
}

// No path found is not no path. The rung stays unclimbed rather than being
// refuted, because a syntactic graph cannot see interface dispatch.
func TestAnUnfoundPathDoesNotRefuteTheRung(t *testing.T) {
	dir := goModule(t, map[string]string{
		"go.mod": "module example.com/app\n\ngo 1.21\n",
		"main.go": `package main

func main() {}
`,
	})
	g := callgraph.BuildGo(dir)
	if _, ok := goCallReachable(g, dir, []string{"crypto/md5"}); ok {
		t.Fatal("a path was reported to a package nothing calls")
	}
}

// Only a CONCRETE entry climbs the rung. An exported function is reachable by
// somebody in principle, which is a weaker claim and belongs to a rung above.
func TestAnExportedOnlyCallerDoesNotClimb(t *testing.T) {
	dir := goModule(t, map[string]string{
		"go.mod": "module example.com/lib\n\ngo 1.21\n",
		"lib.go": `package lib

import "crypto/md5"

// Exported, and nothing in this module calls it.
func Digest(b []byte) [16]byte { return md5.Sum(b) }
`,
	})
	g := callgraph.BuildGo(dir)
	if path, ok := goCallReachable(g, dir, []string{"crypto/md5"}); ok {
		t.Errorf("an exported-only caller climbed to call_reachable with path %v. "+
			"Nothing in this build reaches it; that an outside caller could is the "+
			"rung above, and conflating them turns 'the code exists' into "+
			"'the code runs'.", path)
	}
}
