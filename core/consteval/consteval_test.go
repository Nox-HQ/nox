package consteval

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// offsetOfMarker returns the byte offset of marker in src, so a test can point
// at a call the way an analyzer does — by position, not by AST node.
func offsetOfMarker(t *testing.T, src, marker string) int {
	t.Helper()
	i := strings.Index(src, marker)
	if i < 0 {
		t.Fatalf("marker %q not in source", marker)
	}
	return i
}

func TestCallArgumentsAreConstant(t *testing.T) {
	tests := []struct {
		name       string
		src        string
		marker     string
		constant   bool
		determined bool
	}{
		{
			name: "a const identifier resolves",
			// The case that motivated the package: four hand-written waivers in
			// nox's own repository said this in prose.
			src:    "package p\n\nimport \"fmt\"\n\nconst bashCompletion = `# completion script`\n\nfunc f() { fmt.Print(bashCompletion) }\n",
			marker: "fmt.Print", constant: true, determined: true,
		},
		{
			name:   "a string literal resolves",
			src:    "package p\n\nimport \"fmt\"\n\nfunc f() { fmt.Print(\"hello\") }\n",
			marker: "fmt.Print", constant: true, determined: true,
		},
		{
			name:   "concatenated constants fold",
			src:    "package p\n\nimport \"fmt\"\n\nconst a = \"x\"\n\nfunc f() { fmt.Print(a + \"y\") }\n",
			marker: "fmt.Print", constant: true, determined: true,
		},
		{
			name: "a var is NOT a constant",
			// A var is a literal today and a mutable slot forever after;
			// anything may assign a model response to it before this runs.
			src:    "package p\n\nimport \"fmt\"\n\nvar greeting = \"hi\"\n\nfunc f() { fmt.Print(greeting) }\n",
			marker: "fmt.Print", constant: false, determined: false,
		},
		{
			name:   "a parameter is not a constant",
			src:    "package p\n\nimport \"fmt\"\n\nfunc f(s string) { fmt.Print(s) }\n",
			marker: "fmt.Print", constant: false, determined: false,
		},
		{
			name:   "one non-constant argument is enough",
			src:    "package p\n\nimport \"fmt\"\n\nconst a = \"x\"\n\nfunc f(s string) { fmt.Print(a, s) }\n",
			marker: "fmt.Print", constant: false, determined: false,
		},
		{
			name:   "a local const resolves",
			src:    "package p\n\nimport \"fmt\"\n\nfunc f() { const local = \"v\"; fmt.Print(local) }\n",
			marker: "fmt.Print", constant: true, determined: true,
		},
		{
			name: "a function result is never assumed constant",
			// Innermost-call selection means this asks about os.Getenv's own
			// argument, which is a literal -- but the finding's offset points at
			// the outer call, so the outer call's argument is a CallExpr.
			src:    "package p\n\nimport (\n\t\"fmt\"\n\t\"os\"\n)\n\nfunc f() { fmt.Print(os.Getenv(\"HOME\")) }\n",
			marker: "fmt.Print(", constant: false, determined: false,
		},
		{
			name:   "no arguments carries nothing",
			src:    "package p\n\nimport \"fmt\"\n\nfunc f() { fmt.Println() }\n",
			marker: "fmt.Println", constant: true, determined: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CallArgumentsAreConstant("f.go", []byte(tt.src), offsetOfMarker(t, tt.src, tt.marker))
			if got.Determined != tt.determined {
				t.Fatalf("Determined = %v, want %v (reason: %s)", got.Determined, tt.determined, got.Reason)
			}
			if got.Determined && got.Constant != tt.constant {
				t.Errorf("Constant = %v, want %v", got.Constant, tt.constant)
			}
			if !got.Determined && got.Reason == "" {
				t.Error("an undetermined result must say why")
			}
		})
	}
}

// A constant declared in ANOTHER file of the package is a real constant this
// resolver cannot see. It must answer undetermined, never "not constant":
// callers refute on the answer, and refuting drops a finding.
func TestCrossFileConstantIsUndeterminedNotFalse(t *testing.T) {
	src := "package p\n\nimport \"fmt\"\n\nfunc f() { fmt.Print(declaredElsewhere) }\n"
	got := CallArgumentsAreConstant("f.go", []byte(src), offsetOfMarker(t, src, "fmt.Print"))
	if got.Determined {
		t.Fatalf("claimed to determine a name it cannot see: %+v", got)
	}
	if !strings.Contains(got.Reason, "declaredElsewhere") {
		t.Errorf("reason does not name the unresolved identifier: %q", got.Reason)
	}
}

// Every language without an engine answers undetermined. Reading that as "not
// constant" would be harmless; reading it as "constant" would drop findings in
// every language nox cannot parse, which is most of them.
func TestUnsupportedLanguagesAreUndetermined(t *testing.T) {
	for _, path := range []string{"a.py", "a.js", "a.rb", "a.yaml", "Dockerfile"} {
		t.Run(path, func(t *testing.T) {
			got := CallArgumentsAreConstant(path, []byte("print('hello')\n"), 0)
			if got.Determined {
				t.Errorf("%s: claimed a determination with no evaluator for the language", path)
			}
			if got.Constant {
				t.Errorf("%s: an undetermined result must not read as constant", path)
			}
		})
	}
	if Supported(lexctx.LangPython) {
		t.Error("Python reported as supported; no evaluator exists for it")
	}
	if !Supported(lexctx.LangGo) {
		t.Error("Go reported as unsupported; go/ast is the engine this package is built on")
	}
}

// Content that does not parse must degrade, not decide.
func TestUnparseableGoIsUndetermined(t *testing.T) {
	got := CallArgumentsAreConstant("f.go", []byte("package p\nfunc f( {{{ \n"), 5)
	if got.Determined && got.Constant {
		t.Errorf("unparseable Go decided constant: %+v", got)
	}
}

// The resolver must not read past the call it was asked about. A constant in
// one call says nothing about a variable in the next.
func TestResolutionIsScopedToTheEnclosingCall(t *testing.T) {
	src := "package p\n\nimport \"fmt\"\n\nconst safe = \"x\"\n\nfunc f(user string) {\n\tfmt.Print(safe)\n\tfmt.Println(user)\n}\n"

	first := CallArgumentsAreConstant("f.go", []byte(src), offsetOfMarker(t, src, "fmt.Print("))
	if !first.Determined || !first.Constant {
		t.Errorf("the constant call was not resolved: %+v", first)
	}
	second := CallArgumentsAreConstant("f.go", []byte(src), offsetOfMarker(t, src, "fmt.Println("))
	if second.Determined && second.Constant {
		t.Errorf("a variable argument was reported constant: %+v", second)
	}
}
