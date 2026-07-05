package bench

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestParseExpectationsFromLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		line string
		want []string // rule IDs, in order
	}{
		{"no annotation", `x = 1`, nil},
		{"python comment", `secret = "..."  # nox-expect: SEC-001`, []string{"SEC-001"}},
		{"js line comment", `const p = a + b; // nox-expect: AI-002`, []string{"AI-002"}},
		{"go comment", `os.System(x) // nox-expect: SEC-078`, []string{"SEC-078"}},
		{"multiple rules comma-separated", `y // nox-expect: SEC-001, SEC-508`, []string{"SEC-001", "SEC-508"}},
		{"multiple rules space-separated", `y # nox-expect: AI-002 AI-003`, []string{"AI-002", "AI-003"}},
		{"extra whitespace tolerated", `z   #   nox-expect:    SEC-081   `, []string{"SEC-081"}},
		{"annotation without comment marker still parses", `nox-expect: SEC-001`, []string{"SEC-001"}},
		{"case-insensitive keyword", `q # NOX-EXPECT: SEC-001`, []string{"SEC-001"}},
		{"ignores trailing prose after rule ids is not supported; rule tokens only", `a # nox-expect: SEC-001 because reasons`, []string{"SEC-001", "because", "reasons"}},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := parseExpectationRuleIDs(tt.line)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseExpectationRuleIDs(%q) = %v, want %v", tt.line, got, tt.want)
			}
		})
	}
}

func TestParseCorpus(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// A sample with two annotated lines.
	writeFile(t, dir, "secret.py", `import os
AWS_KEY = "AKIA..."  # nox-expect: SEC-001
password = "hunter2"  # nox-expect: SEC-081
clean = 1
`)
	// A clean sample: no annotations at all.
	writeFile(t, dir, "clean.py", `x = 2
y = 3
`)
	// The corpus README must be ignored, not parsed as a sample.
	writeFile(t, dir, "README.md", "# nox-expect: SEC-999 (this is documentation, must be ignored)\n")

	got, err := ParseCorpus(dir)
	if err != nil {
		t.Fatalf("ParseCorpus: %v", err)
	}

	// Paths are relative to the corpus dir so the report is portable.
	want := []Expectation{
		{RuleID: "SEC-001", FilePath: "secret.py", Line: 2},
		{RuleID: "SEC-081", FilePath: "secret.py", Line: 3},
	}
	sortExpectations(got)
	sortExpectations(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseCorpus = %+v, want %+v", got, want)
	}
}

func TestParseCorpusMissingDir(t *testing.T) {
	t.Parallel()
	if _, err := ParseCorpus(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("expected error for missing corpus dir, got nil")
	}
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
}

func sortExpectations(es []Expectation) {
	sort.Slice(es, func(i, j int) bool {
		if es[i].FilePath != es[j].FilePath {
			return es[i].FilePath < es[j].FilePath
		}
		if es[i].Line != es[j].Line {
			return es[i].Line < es[j].Line
		}
		return es[i].RuleID < es[j].RuleID
	})
}
