package taintflow

import "testing"

// TestAnalyzerLuaTruePositive proves the analyzer runs the taint engine on a .lua
// artifact end-to-end (discovery → lexctx LangLua → extractLua → engine →
// finding), with no code path change beyond the catalog + extractor: a CLI
// argument concatenated into os.execute fires TAINT-002.
func TestAnalyzerLuaTruePositive(t *testing.T) {
	dir := t.TempDir()
	art := writeArtifact(t, dir, "deploy.lua", `local function run()
  local target = arg[1]
  os.execute("deploy " .. target)
end
`)
	ids := scan(t, art)
	found := false
	for _, id := range ids {
		if id == "TAINT-002" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want TAINT-002, got %v", ids)
	}
}

// TestAnalyzerLuaCleanNoFinding proves the tonumber sanitizer guardrail: a value
// coerced to a number before the command sink fires nothing.
func TestAnalyzerLuaCleanNoFinding(t *testing.T) {
	dir := t.TempDir()
	art := writeArtifact(t, dir, "safe.lua", `local function run()
  local raw = arg[1]
  local n = tonumber(raw)
  os.execute("sleep " .. n)
end
`)
	ids := scan(t, art)
	if len(ids) != 0 {
		t.Fatalf("want no findings, got %v", ids)
	}
}
