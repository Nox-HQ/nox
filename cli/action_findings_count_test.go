package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The nox GitHub Action (action.sh) counted findings with
//
//	findings_count=$(grep -c '"RuleID"' findings.json 2>/dev/null || echo "0")
//
// grep -c prints the count but EXITS 1 when there are zero matches, so on a
// clean scan the `|| echo "0"` fallback fired on top of grep's own "0" and made
// findings_count the two-line value "0\n0". Writing that to $GITHUB_OUTPUT
// emitted a bare second line and failed the step with
// "Unable to process file command 'output' ... Invalid format '0'" — the action
// broke on every repository whose scan produced no findings. This guards the
// fix from both directions.
func TestActionFindingsCount_NoDoublingOnZero(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "action.sh"))
	if err != nil {
		t.Fatalf("read action.sh: %v", err)
	}
	if strings.Contains(string(src), `|| echo "0")`) {
		t.Error(`action.sh still uses the "|| echo \"0\"" findings-count fallback that doubles the count to "0\n0" on a zero-findings scan`)
	}

	// Behavioral: the corrected count pipeline must yield exactly one clean
	// integer line for a zero-findings file, so the GITHUB_OUTPUT write is valid.
	dir := t.TempDir()
	f := filepath.Join(dir, "findings.json")
	if err := os.WriteFile(f, []byte(`{"findings":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	script := `findings_count=$(grep -c '"RuleID"' "` + f + `" 2>/dev/null || true)
findings_count=${findings_count:-0}
printf 'findings-count=%s\n' "$findings_count"`
	out, err := exec.Command("bash", "-c", script).Output()
	if err != nil {
		t.Fatalf("run count pipeline: %v", err)
	}
	got := string(out)
	if extra := strings.Count(strings.TrimRight(got, "\n"), "\n"); extra != 0 {
		t.Errorf("expected single-line output; got %d extra newline(s): %q", extra, got)
	}
	if strings.TrimSpace(got) != "findings-count=0" {
		t.Errorf("got %q, want findings-count=0", got)
	}
}
