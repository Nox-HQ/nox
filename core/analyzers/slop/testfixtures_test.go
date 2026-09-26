package slop

import (
	"context"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/reasoning"
)

// A jscodeshift fixture is text a transform is run over, not code anybody
// installs. vercel/ai's codemod reads each __testfixtures__ file with
// readFileSync and hands the string to jscodeshift, and its fixtures import
// `other-pkg`, `not-ai` and `some-other-package` on purpose — to prove the
// transform leaves imports it does not own alone. All 33 of vercel/ai's
// SLOP-001 findings in packages/codemod were those names.
func TestATransformFixtureImportIsNotADependency(t *testing.T) {
	pkgs := findingsFor(t, map[string]string{
		"packages/codemod/src/test/__testfixtures__/rename.input.ts":  "import { x } from 'other-pkg';\n",
		"packages/codemod/src/test/__testfixtures__/rename.output.ts": "import { x } from 'not-ai';\n",
		"packages/codemod/src/lib/cli.ts":                             "import { y } from 'phantom-cli-pkg';\n",
	})
	for _, p := range []string{"other-pkg", "not-ai"} {
		if hasPkg(pkgs, p) {
			t.Errorf("fixture import %q flagged; got %v", p, pkgs)
		}
	}
	if !hasPkg(pkgs, "phantom-cli-pkg") {
		t.Errorf("the codemod's own import must still be flagged; got %v", pkgs)
	}
}

// The directory has to BE __testfixtures__. A file merely named like one, or a
// directory that contains the word, is ordinary source.
func TestOnlyTheFixtureDirectoryIsExempt(t *testing.T) {
	pkgs := findingsFor(t, map[string]string{
		"src/__testfixtures__.ts":          "import a from 'phantom-a';\n",
		"src/my__testfixtures__old/x.ts":   "import b from 'phantom-b';\n",
		"src/__testfixtures__/nested/y.ts": "import c from 'phantom-c';\n",
	})
	for _, p := range []string{"phantom-a", "phantom-b"} {
		if !hasPkg(pkgs, p) {
			t.Errorf("%q is not inside a __testfixtures__ directory and must be flagged; got %v", p, pkgs)
		}
	}
	if hasPkg(pkgs, "phantom-c") {
		t.Errorf("a file nested below __testfixtures__ is still a fixture; got %v", pkgs)
	}
}

// Dropping a candidate without saying why is how stage accounting found four
// silent refiners. The fixture exemption records a refutation per import.
func TestAFixtureExemptionIsRecorded(t *testing.T) {
	arts := writeTree(t, map[string]string{
		"src/test/__testfixtures__/a.input.ts": "import x from 'other-pkg';\n",
	})
	a := NewAnalyzer()
	store := reasoning.New()
	a.RecordReasoningTo(store)
	if _, err := a.ScanArtifacts(context.Background(), arts); err != nil {
		t.Fatal(err)
	}
	var recorded bool
	for _, s := range store.Subjects() {
		for _, c := range store.About(s).Claims {
			if c.Refutes() && strings.Contains(c.Statement, "__testfixtures__") {
				recorded = true
			}
		}
	}
	if !recorded {
		t.Error("the fixture import was dropped and nothing recorded why")
	}
}
