package secrets

import (
	"strings"
	"testing"
)

// A notebook stores each source line as a JSON string, so a key written as
// api_key="..." in the cell is api_key=\"...\" in the file, and rules that
// match the quote directly after the operator never saw it. The 2026-09-27
// head-to-head found a Vercel AI Gateway key in a llama_index notebook this
// way: TruffleHog reported it, nox did not, and the same line in a .py file
// nox reports. The key below is invented; the shape is the real one's.
func TestANotebookCellIsScannedAsTheCodeItHolds(t *testing.T) {
	const key = "aB3dE5fG7hJ9kL1mN3pQ5rS7"
	py := "llm = Gateway(\n    api_key=\"" + key + "\",\n)\n"
	line := `    "    api_key=\"` + key + `\",\n",`
	nb := "{\n \"cells\": [\n  {\n   \"source\": [\n" + line + "\n    \")\"\n   ]\n  }\n ]\n}\n"

	want := map[string]bool{}
	for _, f := range scanOne(t, "demo.py", py) {
		want[f.RuleID] = true
	}
	if len(want) == 0 {
		t.Fatal("the .py form reports nothing; the test has no baseline")
	}

	got := scanOne(t, "demo.ipynb", nb)
	col := strings.Index(line, "api_key") + 1
	for id := range want {
		found := false
		for _, f := range got {
			if f.RuleID != id {
				continue
			}
			found = true
			if f.Location.StartLine != 5 || f.Location.StartColumn != col {
				t.Errorf("%s at %d:%d, want 5:%d (the position in the file on disk)",
					id, f.Location.StartLine, f.Location.StartColumn, col)
			}
		}
		if !found {
			t.Errorf("%s reports the .py line but not the same line in a notebook", id)
		}
	}
}
