package main

import "testing"

func TestRunExplain_NoPath(t *testing.T) {
	code := run([]string{"explain"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for explain without path, got %d", code)
	}
}

func TestRunExplain_MissingAPIKey(t *testing.T) {
	// Ensure OPENAI_API_KEY is not set for this test.
	t.Setenv("OPENAI_API_KEY", "")

	dir := t.TempDir()
	code := run([]string{"explain", dir})
	if code != 2 {
		t.Fatalf("expected exit code 2 for missing API key, got %d", code)
	}
}
