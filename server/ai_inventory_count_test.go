package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// The MCP server counted only inventory Components, so an agent scanning an
// app that calls gpt-4o was told "0 AI components" and got an ML-BOM with no
// model in it — the same blind spot the CLI had. It reads the shared count.
func TestMCP_ModelCallIsCountedAndInTheMLBOM(t *testing.T) {
	s := New("0.1.0", nil)
	dir := t.TempDir()
	writeFile(t, dir, "app.py", "from openai import OpenAI\nclient = OpenAI()\n"+
		"resp = client.chat.completions.create(model=\"gpt-4o\", messages=[])\n")

	r, err := s.handleScan(context.Background(), scanInput{Path: dir})
	if err != nil || !strings.Contains(r, "1 AI component (1 model: gpt-4o via openai)") {
		t.Fatalf("scan text does not report the model: %v / %s", err, r)
	}

	out, err := s.handleSummary(context.Background(), emptyInput{})
	if err != nil {
		t.Fatal(err)
	}
	var sum struct {
		AIComponents int `json:"ai_components"`
	}
	if err := json.Unmarshal([]byte(textOf(out)), &sum); err != nil {
		t.Fatalf("summary not JSON: %v\n%s", err, textOf(out))
	}
	if sum.AIComponents != 1 {
		t.Errorf("summary ai_components = %d, want 1", sum.AIComponents)
	}

	bom, err := s.handleGetSBOM(context.Background(), getSBOMInput{Format: "cdx"})
	if err != nil || !strings.Contains(bom, `"machine-learning-model"`) || !strings.Contains(bom, `"gpt-4o"`) {
		t.Errorf("CycloneDX from MCP lacks the gpt-4o machine-learning-model component: %v", err)
	}
}
