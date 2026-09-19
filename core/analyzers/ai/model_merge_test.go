package ai

import "testing"

// A single `client.chat.completions.create(model="gpt-4o")` is reached by both
// extractors: the config-assignment pattern in extractModelReferences and the
// SDK-invocation pattern in extractSDKInvocations. Before these merged, nox
// 1.37.0 emitted gpt-4o twice for this file — one row with the license and
// registry, one with the line and auth env var, and neither complete.
func TestOneCallSiteIsOneModelRow(t *testing.T) {
	src := []byte(`import os
from openai import OpenAI

client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
resp = client.chat.completions.create(model="gpt-4o", temperature=0.9)
`)

	inv := NewInventory()
	inv.AddModels(extractModelReferences("agent.py", src))
	inv.AddModels(extractSDKInvocations("agent.py", src))

	var got []ModelReference
	for _, m := range inv.ModelProvenance {
		if m.Name == "gpt-4o" {
			got = append(got, m)
		}
	}
	if len(got) != 1 {
		t.Fatalf("expected one gpt-4o row, got %d: %+v", len(got), got)
	}

	// The merged row must be the union, not whichever extractor ran first.
	m := got[0]
	if m.License == "" {
		t.Error("lost the license, which only extractModelReferences supplies")
	}
	if m.Line == 0 {
		t.Error("lost the line number, which only extractSDKInvocations supplies")
	}
	if m.AuthEnvVar != "OPENAI_API_KEY" {
		t.Errorf("lost the auth env var, got %q", m.AuthEnvVar)
	}
	if m.Registry != "openai" {
		t.Errorf("registry = %q, want openai", m.Registry)
	}
}

// Merging must not collapse distinct models, or the inventory stops being an
// inventory.
func TestDistinctModelsAndFilesStaySeparate(t *testing.T) {
	inv := NewInventory()
	inv.AddModels([]ModelReference{
		{Name: "gpt-4o", Path: "a.py"},
		{Name: "claude-opus-4", Path: "a.py"},
		{Name: "gpt-4o", Path: "b.py"},
	})
	if len(inv.ModelProvenance) != 3 {
		t.Fatalf("expected 3 rows, got %d: %+v", len(inv.ModelProvenance), inv.ModelProvenance)
	}
}

// A pin found by one extractor is a pin, even though the other does not look
// for one — so Pinned must not be overwritten by the later false.
func TestAPinSurvivesAnUnpinnedSighting(t *testing.T) {
	inv := NewInventory()
	inv.AddModels([]ModelReference{{Name: "m", Path: "p", Pinned: true, Hash: "abc123"}})
	inv.AddModels([]ModelReference{{Name: "m", Path: "p", Pinned: false, Line: 42}})

	if len(inv.ModelProvenance) != 1 {
		t.Fatalf("expected 1 row, got %d", len(inv.ModelProvenance))
	}
	got := inv.ModelProvenance[0]
	if !got.Pinned {
		t.Error("the pin was overwritten by an extractor that does not detect pins")
	}
	if got.Hash != "abc123" {
		t.Errorf("hash = %q, want abc123", got.Hash)
	}
	if got.Line != 42 {
		t.Errorf("line = %d, want 42", got.Line)
	}
}

// Two calls to the same model in one file become one row reporting the first
// line. This is the deliberate cost of merging, and it is the granularity the
// inventory already reported at — extractModelReferences has always collapsed
// repeat names within a file, so no caller could ever count call sites here.
// Per-occurrence locations are the finding stream's job, not the AIBOM's.
func TestASecondCallSiteCollapsesToTheFirstLine(t *testing.T) {
	inv := NewInventory()
	inv.AddModels([]ModelReference{
		{Name: "claude-sonnet-5", Path: "examples/messages.py", Line: 5, Registry: "anthropic"},
		{Name: "claude-sonnet-5", Path: "examples/messages.py", Line: 17, Registry: "anthropic"},
	})
	if len(inv.ModelProvenance) != 1 {
		t.Fatalf("expected 1 row, got %d", len(inv.ModelProvenance))
	}
	if got := inv.ModelProvenance[0].Line; got != 5 {
		t.Fatalf("line = %d, want the first sighting (5)", got)
	}
}
