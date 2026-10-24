package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An app calling openai.chat.completions.create(model="gpt-4o") printed
// "0 AI components" and wrote no ai.inventory.json, even with --format all:
// the CLI counted Components and wrote the file only when that was non-zero,
// and a detected model lives in ModelProvenance.

type inventoryFile struct {
	SchemaVersion   string            `json:"schema_version"`
	Components      []json.RawMessage `json:"components"`
	ModelProvenance []struct {
		Name     string `json:"name"`
		Registry string `json:"registry"`
	} `json:"model_provenance"`
	Checks []string `json:"checks"`
}

func scanForInventory(t *testing.T, files map[string]string) (string, inventoryFile) {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	for rel, body := range files {
		p := filepath.Join(src, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(dir, "out")
	var code int
	stdout := captureStdout(t, func() {
		code = run([]string{"scan", "--no-cache", "--offline", "--output", out, src})
	})
	if code != 0 && code != 1 {
		t.Fatalf("scan exit %d\n%s", code, stdout)
	}
	data, err := os.ReadFile(filepath.Join(out, "ai.inventory.json"))
	if err != nil {
		t.Fatalf("ai.inventory.json not written: %v\n%s", err, stdout)
	}
	var inv inventoryFile
	if err := json.Unmarshal(data, &inv); err != nil {
		t.Fatalf("ai.inventory.json is not valid JSON: %v\n%s", err, data)
	}
	return stdout, inv
}

func TestScan_ModelCallIsCountedAndInventoried(t *testing.T) {
	stdout, inv := scanForInventory(t, map[string]string{
		"app.py": "from openai import OpenAI\nclient = OpenAI()\n" +
			"resp = client.chat.completions.create(model=\"gpt-4o\", messages=[])\n",
	})
	if !strings.Contains(stdout, "1 AI component (1 model: gpt-4o via openai)") {
		t.Errorf("console does not report the model:\n%s", stdout)
	}
	if len(inv.ModelProvenance) != 1 || inv.ModelProvenance[0].Name != "gpt-4o" {
		t.Errorf("inventory model_provenance = %+v", inv.ModelProvenance)
	}
}

func TestScan_NoAIStillWritesAnInventoryThatSaysItLooked(t *testing.T) {
	stdout, inv := scanForInventory(t, map[string]string{
		"main.go": "package main\n\n// Compare with openai later.\nfunc main() {}\n",
	})
	if !strings.Contains(stdout, ", 0 AI components") {
		t.Errorf("console:\n%s", stdout)
	}
	if inv.Components == nil || len(inv.Components) != 0 || len(inv.ModelProvenance) != 0 {
		t.Errorf("want an empty inventory, got %+v", inv)
	}
	if len(inv.Checks) == 0 {
		t.Error("an empty inventory must record which checks ran, or it reads the same as one that never looked")
	}
}

func TestScan_SkippedAIScopeWritesAnInventoryWithNoChecks(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("from openai import OpenAI\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	var code int
	stdout := captureStdout(t, func() {
		code = run([]string{"scan", "--no-cache", "--offline", "--skip", "ai", "--output", out, dir})
	})
	if code != 0 && code != 1 {
		t.Fatalf("scan exit %d\n%s", code, stdout)
	}
	data, err := os.ReadFile(filepath.Join(out, "ai.inventory.json"))
	if err != nil {
		t.Fatalf("ai.inventory.json not written: %v", err)
	}
	var inv inventoryFile
	if err := json.Unmarshal(data, &inv); err != nil {
		t.Fatal(err)
	}
	if inv.Checks == nil || len(inv.Checks) != 0 {
		t.Errorf("checks = %v, want []: the AI scope did not run", inv.Checks)
	}
}
