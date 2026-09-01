package ai

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/reasoning"
)

func scanGo(t *testing.T, name, src string) []findings.Finding {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("writing sample: %v", err)
	}
	fs, _, err := NewAnalyzer().ScanArtifacts(context.Background(),
		[]discovery.Artifact{{Path: name, AbsPath: path}})
	if err != nil {
		t.Fatalf("ScanArtifacts: %v", err)
	}
	var out []findings.Finding
	for _, f := range fs.Findings() {
		if f.RuleID == "AI-006" {
			out = append(out, f)
		}
	}
	return out
}

// The case constant evaluation exists for, and the one lexical analysis cannot
// reach: the argument is a NAME, so lexing sees code and keeps the finding, but
// the name is bound by `const` and therefore cannot hold a runtime prompt.
//
// AI-006's pattern matches `prompt` at a word boundary, which the identifier
// `promptTemplate` satisfies — so the rule fires on the NAME of a constant.
func TestConstantPromptTemplateIsRefuted(t *testing.T) {
	src := "package p\n\nimport \"fmt\"\n\n" +
		"const promptTemplate = \"You are a helpful assistant.\"\n\n" +
		"func f() { fmt.Print(promptTemplate) }\n"

	if got := scanGo(t, "a.go", src); len(got) != 0 {
		t.Errorf("AI-006 fired %d time(s) on a logging call whose only argument is a "+
			"compile-time constant; a constant cannot carry a runtime prompt: %+v", len(got), got)
	}
}

// The failure direction that matters. A var is a literal today and a mutable
// slot forever after, so it must stay reported.
func TestVariablePromptIsNotRefuted(t *testing.T) {
	src := "package p\n\nimport \"fmt\"\n\n" +
		"var promptTemplate = \"You are a helpful assistant.\"\n\n" +
		"func f() { fmt.Print(promptTemplate) }\n"

	if got := scanGo(t, "a.go", src); len(got) == 0 {
		t.Error("AI-006 was refuted on a VAR argument; a var can be reassigned " +
			"to a model response before the log call runs")
	}
}

// A value the resolver cannot see must stay reported. A constant declared in
// another file of the package is undetermined here, and undetermined is not
// a refutation.
func TestUnresolvedNameIsNotRefuted(t *testing.T) {
	src := "package p\n\nimport \"fmt\"\n\nfunc f() { fmt.Print(promptFromElsewhere) }\n"

	if got := scanGo(t, "a.go", src); len(got) == 0 {
		t.Error("AI-006 was refuted on a name the resolver could not see; " +
			"\"I could not tell\" is not \"there is nothing here\"")
	}
}

// Languages with no constant engine must be untouched by this refiner.
func TestPythonIsUnaffectedByConstantEvaluation(t *testing.T) {
	src := "PROMPT_TEMPLATE = \"You are a helpful assistant.\"\n" +
		"print(PROMPT_TEMPLATE)\n"

	if got := scanGo(t, "a.py", src); len(got) == 0 {
		t.Error("AI-006 was refuted in Python, where nox has no constant evaluator; " +
			"a language without an engine must answer undetermined")
	}
}

// The refutation must be recorded, not silent — the reason for a suppression
// has to survive the suppression.
func TestConstantRefutationRecordsItsReason(t *testing.T) {
	src := "package p\n\nimport \"fmt\"\n\n" +
		"const promptTemplate = \"You are a helpful assistant.\"\n\n" +
		"func f() { fmt.Print(promptTemplate) }\n"

	dir := t.TempDir()
	path := filepath.Join(dir, "a.go")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	store := reasoning.New()
	a := NewAnalyzer()
	a.RecordReasoningTo(store)
	if _, _, err := a.ScanArtifacts(context.Background(),
		[]discovery.Artifact{{Path: "a.go", AbsPath: path}}); err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, subject := range store.Subjects() {
		for _, c := range store.About(subject).Claims {
			if c.Refutes() && strings.Contains(c.Statement, "compile-time constant") {
				found = true
			}
		}
	}
	if !found {
		t.Error("the constant refutation left no claim; an operator cannot tell " +
			"this from the rule never having fired")
	}
}

// A trailing comment must not supply the word that makes the rule fire.
//
// This is a real class found in nox's own repository: four waivers read
// `fmt.Print(bashCompletion) // nox:ignore AI-006 -- shell completion script`,
// and the word "completion" in the JUSTIFICATION was the only reason AI-006
// matched. The waiver caused the finding it waived — delete the comment and
// nothing fires, because `bashCompletion` has no word boundary before
// "Completion" and never matched the pattern at all.
func TestTriggerWordInATrailingCommentDoesNotCreateAFinding(t *testing.T) {
	src := "package p\n\nimport \"fmt\"\n\n" +
		"const bashCompletion = `# a shell script`\n\n" +
		"func f() { fmt.Print(bashCompletion) } // shell completion script\n"

	if got := scanGo(t, "a.go", src); len(got) != 0 {
		t.Errorf("AI-006 fired %d time(s) where the only trigger word is in a "+
			"trailing comment; the logged value is a constant: %+v", len(got), got)
	}
}
