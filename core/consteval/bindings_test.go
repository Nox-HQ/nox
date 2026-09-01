package consteval

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// The point of this file: nox is language-agnostic, so a constant evaluator
// that answers only for Go is not a capability.
func TestConstantEvaluationSpansLanguages(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		src      string
		marker   string
		constant bool
		basis    Basis
	}{
		{
			name:   "javascript const",
			path:   "a.js",
			src:    "const PROMPT = \"you are helpful\";\nconsole.log(PROMPT);\n",
			marker: "console.log", constant: true, basis: BasisDeclared,
		},
		{
			name:   "typescript const",
			path:   "a.ts",
			src:    "const promptTemplate = \"you are helpful\";\nconsole.log(promptTemplate);\n",
			marker: "console.log", constant: true, basis: BasisDeclared,
		},
		{
			name:   "javascript let is not constant",
			path:   "a.js",
			src:    "let prompt = \"you are helpful\";\nconsole.log(prompt);\n",
			marker: "console.log", constant: false,
		},
		{
			name:   "python ALL_CAPS bound once",
			path:   "a.py",
			src:    "PROMPT_TEMPLATE = \"you are helpful\"\nprint(PROMPT_TEMPLATE)\n",
			marker: "print(", constant: true, basis: BasisSingleBinding,
		},
		{
			name: "python name rebound is not constant",
			// The single-binding rule is what stands in for a keyword Python
			// does not have. Two bindings and the guarantee is gone.
			path:   "a.py",
			src:    "PROMPT = \"a\"\nPROMPT = \"b\"\nprint(PROMPT)\n",
			marker: "print(", constant: false,
		},
		{
			name:   "python lowercase name is not a constant by convention",
			path:   "a.py",
			src:    "prompt = \"you are helpful\"\nprint(prompt)\n",
			marker: "print(", constant: false,
		},
		{
			name:   "java static final",
			path:   "A.java",
			src:    "class A { static final String PROMPT = \"hi\";\n void f() { System.out.println(PROMPT); } }\n",
			marker: "System.out.println", constant: true, basis: BasisDeclared,
		},
		{
			name:   "ruby capitalized constant",
			path:   "a.rb",
			src:    "PROMPT = \"you are helpful\"\nputs(PROMPT)\n",
			marker: "puts(", constant: true, basis: BasisSingleBinding,
		},
		{
			name:   "kotlin val",
			path:   "a.kt",
			src:    "val prompt = \"hi\"\nfun f() { println(prompt) }\n",
			marker: "println(", constant: true, basis: BasisDeclared,
		},
		{
			name:   "php const",
			path:   "a.php",
			src:    "<?php\nconst PROMPT = \"hi\";\necho(PROMPT);\n",
			marker: "echo(", constant: true, basis: BasisDeclared,
		},
		{
			name:   "rust const",
			path:   "a.rs",
			src:    "const PROMPT: &str = \"hi\";\nfn f() { println(PROMPT); }\n",
			marker: "println(", constant: true, basis: BasisDeclared,
		},
		{
			name:   "a string literal argument needs no binding at all",
			path:   "a.js",
			src:    "console.log(\"a literal prompt\");\n",
			marker: "console.log", constant: true, basis: BasisDeclared,
		},
		{
			name:   "an unresolved name stays undetermined",
			path:   "a.js",
			src:    "console.log(fromElsewhere);\n",
			marker: "console.log", constant: false,
		},
		{
			name:   "a call argument is never assumed constant",
			path:   "a.js",
			src:    "const P = \"hi\";\nconsole.log(getPrompt());\n",
			marker: "console.log", constant: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			off := strings.Index(tt.src, tt.marker)
			if off < 0 {
				t.Fatalf("marker %q not in source", tt.marker)
			}
			got := CallArgumentsAreConstant(tt.path, []byte(tt.src), off)

			if tt.constant {
				if !got.Determined || !got.Constant {
					t.Fatalf("want constant, got %+v", got)
				}
				if got.Basis != tt.basis {
					t.Errorf("Basis = %q, want %q", got.Basis, tt.basis)
				}
				return
			}
			if got.Determined && got.Constant {
				t.Errorf("wrongly reported constant: %+v", got)
			}
			if got.Reason == "" {
				t.Error("a non-answer must say why")
			}
		})
	}
}

// A comment must never supply the binding, and must never supply an argument.
// This is the class that produced four self-caused waivers in this repository.
func TestCommentsAndStringsAreNotCode(t *testing.T) {
	// The "binding" is inside a comment; the name is really unbound.
	src := "// const PROMPT = \"x\"\nconsole.log(PROMPT);\n"
	got := CallArgumentsAreConstant("a.js", []byte(src), strings.Index(src, "console.log"))
	if got.Determined && got.Constant {
		t.Errorf("a declaration inside a comment was read as a binding: %+v", got)
	}

	// A `)` inside a string must not close the call early.
	src2 := "const A = \"a) not the end\";\nconsole.log(A, undeclared);\n"
	got2 := CallArgumentsAreConstant("a.js", []byte(src2), strings.Index(src2, "console.log"))
	if got2.Determined && got2.Constant {
		t.Errorf("a paren inside a string closed the call early, hiding an argument: %+v", got2)
	}
}

// Basis must degrade to the weakest argument: one convention-based name makes
// the whole call convention-based, not declared.
func TestBasisTakesTheWeakestArgument(t *testing.T) {
	src := "A_CONST = \"x\"\nB_CONST = \"y\"\nprint(A_CONST, B_CONST)\n"
	got := CallArgumentsAreConstant("a.py", []byte(src), strings.Index(src, "print("))
	if !got.Determined || !got.Constant {
		t.Fatalf("want constant, got %+v", got)
	}
	if got.Basis != BasisSingleBinding {
		t.Errorf("Basis = %q, want %q — Python has no immutable-binding keyword",
			got.Basis, BasisSingleBinding)
	}
}

// Supported must name every language with an engine, and no others.
func TestSupportedNamesEveryEngine(t *testing.T) {
	for _, l := range []lexctx.Lang{
		lexctx.LangGo, lexctx.LangJavaScript, lexctx.LangPython, lexctx.LangJava,
		lexctx.LangRuby, lexctx.LangKotlin, lexctx.LangPHP, lexctx.LangRust,
		lexctx.LangCSharp, lexctx.LangSwift, lexctx.LangScala, lexctx.LangDart,
		lexctx.LangGroovy, lexctx.LangCPP, lexctx.LangObjC,
	} {
		if !Supported(l) {
			t.Errorf("%v has an engine but Supported reports false", l)
		}
	}
	for _, l := range []lexctx.Lang{
		lexctx.LangUnknown, lexctx.LangShell, lexctx.LangYAML, lexctx.LangDockerfile,
	} {
		if Supported(l) {
			t.Errorf("%v has no engine but Supported reports true; the matrix would "+
				"read as covered where nothing can answer", l)
		}
	}
}
