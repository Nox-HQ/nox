package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// A sink call counts whatever reaches it: a constant command is still the
// authority to run commands.
func TestSinkSitesListsCallsWhateverReachesThem(t *testing.T) {
	src := `package s

func run() {
	_ = exec.Command("git", "status").Run()
	_ = exec.Command("ls").Run()
	resp, _ := http.Get("https://example.invalid/health")
	_ = resp
	_ = strings.ToUpper("x")
}`
	eng := NewStructuralEngine(nil)
	sites := eng.SinkSites(ExtractUnits("s.go", lexctx.LangGo, []byte(src)))
	classes := map[string]int{}
	for _, s := range sites {
		classes[string(s.Class)]++
		if s.FilePath != "s.go" || s.Line == 0 {
			t.Errorf("site without a location: %+v", s)
		}
	}
	if classes["command_injection"] != 1 {
		t.Errorf("exec.Command twice should be one site, got %d (%+v)", classes["command_injection"], sites)
	}
	if classes["ssrf"] != 1 {
		t.Errorf("http.Get not listed: %+v", sites)
	}
	if len(classes) != 2 {
		t.Errorf("unexpected classes %v", classes)
	}
	// The flows view of the same code reports nothing: no untrusted input.
	if flows := eng.AnalyzeFile(ExtractUnits("s.go", lexctx.LangGo, []byte(src))); len(flows) != 0 {
		t.Errorf("constant calls produced flows %v", ruleIDs(flows))
	}
}
