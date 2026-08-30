package reach_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/reach"
)

// TestDetectFindsWhatItClaimsAndStaysQuietOtherwise checks both directions a
// detector for incompleteness can fail in.
//
// A detector for incompleteness has an unusual failure mode: it fails SAFE in
// one direction and useless in the other. A false positive only adds a
// limitation, which only weakens a claim — nox says "I may have missed
// something" when it did not. A limitation on every file, though, carries no
// information and trains a reader to skip the field, which is worse than not
// reporting it at all.
//
// So both halves are checked: it must fire on the constructs it names, and it
// must stay quiet on ordinary source.
func TestDetectFindsWhatItClaimsAndStaysQuietOtherwise(t *testing.T) {
	cases := map[string]reach.Limitation{
		`m := reflect.ValueOf(x).MethodByName("Run")`: reach.Reflection,
		`v = getattr(obj, name)`:                      reach.Reflection,
		`p, _ := plugin.Open(path)`:                   reach.DynamicLoading,
		`mod = importlib.import_module(name)`:         reach.DynamicLoading,
		`ptr := unsafe.Pointer(&b[0])`:                reach.ForeignFunctions,
		`import "C"`:                                  reach.ForeignFunctions,
	}
	for src, want := range cases {
		got := reach.Detect([]byte(src))
		var found bool
		for _, l := range got {
			if l == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q did not report %s (got %v)", src, want, got)
		}
	}

	// Ordinary code, including the shapes an over-broad marker would catch.
	for _, src := range []string{
		"package main\n\nimport (\n\t\"fmt\"\n)\n\nfunc main() { fmt.Println() }",
		"func f(v interface{}) {}",
		"func g(v any) error { return nil }",
		"require (\n\tgithub.com/x/y v1.0.0\n)",
		"const s = \"we use reflection nowhere\"",
	} {
		if got := reach.Detect([]byte(src)); len(got) > 0 {
			t.Errorf("ordinary source reported %v:\n%s", got, src)
		}
	}
}

// TestDetectIsQuietOnNoxItself is the noise measurement, kept executable.
//
// The first version of this detector matched Go's own `import (` block and
// `interface{}`, and reported dynamic_loading on all five cases of a corpus
// where only one has any — including three files containing no dynamic loading
// at all. A detector that fires everywhere is not a detector, and the way that
// was found was measuring it rather than reasoning about the patterns.
func TestDetectIsQuietOnNoxItself(t *testing.T) {
	var files, flagged int
	root := filepath.Join("..", "..")
	err := filepath.Walk(root, func(p string, i os.FileInfo, err error) error {
		if err != nil || i.IsDir() || !strings.HasSuffix(p, ".go") || strings.Contains(p, "testdata") {
			return nil
		}
		b, readErr := os.ReadFile(p)
		if readErr != nil {
			return nil
		}
		files++
		if len(reach.Detect(b)) > 0 {
			flagged++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if files < 100 {
		t.Fatalf("only %d files walked; the measurement is not covering the tree", files)
	}
	rate := 100 * float64(flagged) / float64(files)
	if rate > 15 {
		t.Errorf("%.1f%% of nox's own source is flagged as defeating static analysis "+
			"(%d of %d). A limitation reported on that many files carries no "+
			"information and trains a reader to skip the field", rate, flagged, files)
	}
	t.Logf("nox's own source: %d of %d files flagged (%.1f%%)", flagged, files, rate)
}
