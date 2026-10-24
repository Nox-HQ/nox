package ai

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
)

// The inventory used to detect a model and then drop it from view: every
// output counted only Components, and a model lives in ModelProvenance. An app
// calling openai.chat.completions.create(model: "gpt-4o") printed "0 AI
// components" and wrote no ai.inventory.json, while the taint engine flagged
// the same line as a prompt-injection sink. These tests pin the shared count
// every output now reads, and the detections it rests on.

func scanSources(t *testing.T, files map[string]string) *Inventory {
	t.Helper()
	dir := t.TempDir()
	var artifacts []discovery.Artifact
	for _, rel := range sortedKeys(files) {
		abs := writeFile(t, dir, rel, files[rel])
		artifacts = append(artifacts, discovery.Artifact{Path: rel, AbsPath: abs, Type: discovery.Source})
	}
	_, inv, err := NewAnalyzer().ScanArtifacts(context.Background(), artifacts)
	if err != nil {
		t.Fatalf("ScanArtifacts: %v", err)
	}
	return inv
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

const expressOpenAI = `const express = require("express");
const OpenAI = require("openai");

const router = express.Router();
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

router.post("/ask", async (req, res) => {
  const completion = await openai.chat.completions.create({
    model: "gpt-4o",
    messages: [{ role: "user", content: req.body.question }],
  });
  res.json(completion.choices[0].message);
});

module.exports = router;
`

const pythonOpenAI = `from openai import OpenAI
client = OpenAI()
resp = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": "hi"}])
`

func TestInventory_SDKCallIsCountedAsAComponent(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"express": {"src/routes/assistant.js": expressOpenAI},
		"python":  {"app.py": pythonOpenAI},
	} {
		t.Run(name, func(t *testing.T) {
			inv := scanSources(t, files)
			if got := inv.ComponentCount(); got != 1 {
				t.Fatalf("ComponentCount = %d, want 1 (the gpt-4o model); provenance %+v", got, inv.ModelProvenance)
			}
			if got, want := inv.Summary(), "1 AI component (1 model: gpt-4o via openai)"; got != want {
				t.Errorf("Summary = %q, want %q", got, want)
			}
		})
	}
}

func TestInventory_OneModelInManyFilesCountsOnce(t *testing.T) {
	inv := scanSources(t, map[string]string{
		"a.py": pythonOpenAI,
		"b.py": pythonOpenAI,
	})
	if len(inv.ModelProvenance) != 2 {
		t.Fatalf("want one provenance row per file, got %+v", inv.ModelProvenance)
	}
	if got := inv.ComponentCount(); got != 1 {
		t.Errorf("ComponentCount = %d, want 1: the same model called from two files is one model", got)
	}
}

func TestInventory_SummaryIsOrderIndependent(t *testing.T) {
	a := NewInventory()
	a.AddModels([]ModelReference{
		{Name: "gpt-4o", Registry: "openai", Path: "a.py"},
		{Name: "claude-3-5-sonnet", Registry: "anthropic", Path: "b.py"},
	})
	b := NewInventory()
	b.AddModels([]ModelReference{
		{Name: "claude-3-5-sonnet", Registry: "anthropic", Path: "b.py"},
		{Name: "gpt-4o", Registry: "openai", Path: "a.py"},
	})
	if a.Summary() != b.Summary() {
		t.Fatalf("summary depends on input order: %q vs %q", a.Summary(), b.Summary())
	}
	want := "2 AI components (2 models: claude-3-5-sonnet via anthropic, gpt-4o via openai)"
	if a.Summary() != want {
		t.Errorf("Summary = %q, want %q", a.Summary(), want)
	}
}

func TestInventory_SummaryShapes(t *testing.T) {
	empty := NewInventory()
	if got := empty.Summary(); got != "0 AI components" {
		t.Errorf("empty Summary = %q", got)
	}
	var nilInv *Inventory
	if got := nilInv.ComponentCount(); got != 0 {
		t.Errorf("nil ComponentCount = %d", got)
	}

	comps := NewInventory()
	comps.Add(Component{Name: "mcp.json", Type: "mcp_config", Path: "mcp.json"})
	comps.Add(Component{Name: "langchain", Type: "agent_framework", Path: "app.py"})
	if got := comps.Summary(); got != "2 AI components" {
		t.Errorf("components-only Summary = %q", got)
	}

	unknown := NewInventory()
	unknown.AddModels([]ModelReference{{Name: "my-finetune", Registry: "unknown", Path: "agents/a.yaml"}})
	if got := unknown.Summary(); got != "1 AI component (1 model: my-finetune)" {
		t.Errorf("unknown-provider Summary = %q", got)
	}

	many := NewInventory()
	for _, n := range []string{"gpt-4o", "gpt-4o-mini", "gpt-4.1", "o3-mini", "gpt-3.5-turbo"} {
		many.AddModels([]ModelReference{{Name: n, Registry: "openai", Path: "a.py"}})
	}
	got := many.Summary()
	if !strings.HasPrefix(got, "5 AI components (5 models: ") || !strings.HasSuffix(got, ", +2 more)") {
		t.Errorf("long Summary = %q, want the first three models then +2 more", got)
	}
}

// A file whose only AI signal is the word "openai" in a comment opens the
// polyglot gate, and the config pattern then read any `model: "X"` in it as an
// ML model. While models were invisible that was harmless; counted, it would
// put an ORM model name in the AI-BOM.
func TestInventory_NoPhantomModelsFromAMentionedProvider(t *testing.T) {
	inv := scanSources(t, map[string]string{
		"src/orders.js": "// TODO: we might switch to openai for summaries one day\n" +
			"const opts = { model: \"Invoice\", as: \"invoices\" };\n" +
			"const label = \"Powered by OpenAI\";\n",
		"src/main.go": "package main\n\n// Compare with openai later.\n" +
			"type Cfg struct{ Model string }\n" +
			"var c = Cfg{Model: \"resnet\"}\n",
		"src/settings.py": "# openai is not used here\nmodel_name = \"invoice_classifier\"\n",
	})
	if inv.ComponentCount() != 0 || len(inv.ModelProvenance) != 0 {
		t.Fatalf("phantom AI components from a mentioned provider: %d, %+v", inv.ComponentCount(), inv.ModelProvenance)
	}
}

// A call quoted in a comment is documentation, not a dependency. nox's own
// detector source said `chat.completions.create(model="gpt-...")` in a doc
// comment and was inventoried as calling a model named "gpt-...".
func TestInventory_NoModelsFromCallsInComments(t *testing.T) {
	inv := scanSources(t, map[string]string{
		"detect.go": "package detect\n\n" +
			"// Captures openai `client.chat.completions.create(model=\"gpt-4o\")` call sites.\n" +
			"/* e.g. messages.create(model=\"claude-3-5-sonnet\") */\n" +
			"func Detect() {}\n",
		"loader.py": "# from_pretrained(\"model-name\") loads weights; openai is unused\n" +
			"def load():\n    pass\n",
		"chat.ts": "// openai.chat.completions.create({ model: \"gpt-4o\" })\n" +
			"export const x = 1;\n",
	})
	if inv.ComponentCount() != 0 {
		t.Fatalf("models inventoried from comments: %+v", inv.ModelProvenance)
	}
}

// A recognised model family assigned in AI-bearing source is still a model:
// the phantom guard must not cost the config-style reference.
func TestInventory_KnownModelInSourceConfigIsKept(t *testing.T) {
	inv := scanSources(t, map[string]string{
		"svc/llm.py": "import openai\nMODEL = \"claude-3-5-sonnet\"\n",
	})
	if inv.ComponentCount() != 1 {
		t.Fatalf("want claude-3-5-sonnet kept, got %+v", inv.ModelProvenance)
	}
}

// An inventory must say whether nox looked. Empty Components from a scan
// that ran the AI checks means "found nothing"; the same empty list from a
// scan that never ran them must not read the same way.
func TestInventory_RecordsWhichChecksRan(t *testing.T) {
	inv := scanSources(t, map[string]string{"main.go": "package main\nfunc main() {}\n"})
	if len(inv.Checks) == 0 {
		t.Fatal("a scan that ran the AI analyzer recorded no checks")
	}
	data, err := inv.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if comps, ok := parsed["components"].([]any); !ok || len(comps) != 0 {
		t.Errorf("components = %v, want an empty array", parsed["components"])
	}

	// The zero value is what a scan that skipped the AI scope carries.
	data, err = (&Inventory{}).JSON()
	if err != nil {
		t.Fatal(err)
	}
	parsed = nil
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["schema_version"] != schemaVersion {
		t.Errorf("schema_version = %v, want %s", parsed["schema_version"], schemaVersion)
	}
	if checks, ok := parsed["checks"].([]any); !ok || len(checks) != 0 {
		t.Errorf("checks = %v, want an empty array: nothing ran", parsed["checks"])
	}
	if comps, ok := parsed["components"].([]any); !ok || len(comps) != 0 {
		t.Errorf("components = %v, want an empty array", parsed["components"])
	}
}
