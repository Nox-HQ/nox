package core

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
)

func TestLanguageForExtension(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		want string
	}{
		{"go", "main.go", "go"},
		{"python", "app.py", "python"},
		{"js", "index.js", "javascript"},
		{"jsx", "App.jsx", "javascript"},
		{"mjs", "esm.mjs", "javascript"},
		{"ts", "server.ts", "typescript"},
		{"tsx", "Page.tsx", "typescript"},
		{"rust", "lib.rs", "rust"},
		{"c header maps to c", "foo.h", "c"},
		{"uppercase extension", "MAIN.GO", "go"},
		{"nested path", "src/pkg/handler.py", "python"},
		{"config file has no language", "config.yaml", ""},
		{"no extension", "Makefile", ""},
		{"unknown source", "query.sql", ""},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := LanguageForExtension(tt.path); got != tt.want {
				t.Errorf("LanguageForExtension(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestDefaultLanguageDepth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		language string
		want     SASTDepth
	}{
		{"python", SASTDeep},
		{"javascript", SASTDeep},
		{"typescript", SASTDeep},
		{"go", SASTStandard},
		{"rust", SASTStandard},
		{"java", SASTStandard},
		{"unlisted-language", SASTStandard},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.language, func(t *testing.T) {
			t.Parallel()
			if got := DefaultLanguageDepth(tt.language); got != tt.want {
				t.Errorf("DefaultLanguageDepth(%q) = %q, want %q", tt.language, got, tt.want)
			}
		})
	}
}

func TestSASTConfig_ResolveDepth(t *testing.T) {
	t.Parallel()

	cfg := SASTConfig{Languages: map[string]string{
		"go":         "deep",     // override the default (standard) upward
		"python":     "off",      // override the default (deep) to off
		"typescript": "standard", // override the default (deep) downward
		"Ruby":       "off",      // uppercase key must match lowercase lookup
	}}

	tests := []struct {
		name     string
		language string
		want     SASTDepth
	}{
		{"explicit deep on a standard-default language", "go", SASTDeep},
		{"explicit off overrides deep default", "python", SASTOff},
		{"explicit standard overrides deep default", "typescript", SASTStandard},
		{"case-insensitive language lookup", "ruby", SASTOff},
		{"query language name case-insensitively", "PYTHON", SASTOff},
		{"unlisted deep-default language keeps deep", "javascript", SASTDeep},
		{"unlisted standard-default language keeps standard", "rust", SASTStandard},
		{"empty language resolves standard", "", SASTStandard},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := cfg.ResolveDepth(tt.language); got != tt.want {
				t.Errorf("ResolveDepth(%q) = %q, want %q", tt.language, got, tt.want)
			}
		})
	}
}

func TestSASTConfig_ResolveDepth_NilConfig(t *testing.T) {
	t.Parallel()

	var cfg SASTConfig // Languages is nil
	if got := cfg.ResolveDepth("python"); got != SASTDeep {
		t.Errorf("ResolveDepth(python) with nil config = %q, want deep (default)", got)
	}
	if got := cfg.ResolveDepth("go"); got != SASTStandard {
		t.Errorf("ResolveDepth(go) with nil config = %q, want standard (default)", got)
	}
}

func TestSASTConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		langs   map[string]string
		wantErr bool
	}{
		{"nil config is valid", nil, false},
		{"empty config is valid", map[string]string{}, false},
		{
			name:  "all valid depths",
			langs: map[string]string{"python": "deep", "go": "standard", "rust": "off"},
		},
		{
			name:  "mixed case depth is normalized and valid",
			langs: map[string]string{"go": "Deep", "python": "OFF"},
		},
		{
			name:    "unknown depth is rejected",
			langs:   map[string]string{"go": "shallow"},
			wantErr: true,
		},
		{
			name:    "typo depth is rejected",
			langs:   map[string]string{"python": "depe"},
			wantErr: true,
		},
		{
			name:    "empty depth string is rejected",
			langs:   map[string]string{"go": ""},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := SASTConfig{Languages: tt.langs}.Validate()
			if tt.wantErr && err == nil {
				t.Errorf("Validate() = nil, want error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Validate() = %v, want nil", err)
			}
		})
	}
}

func TestSASTConfig_ResolvedProfile(t *testing.T) {
	t.Parallel()

	cfg := SASTConfig{Languages: map[string]string{
		"go":        "off",
		"terraform": "standard", // language with no extension mapping, still recorded
	}}
	profile := cfg.ResolvedProfile()

	// Defaults are materialized for known languages.
	if profile["python"] != "deep" {
		t.Errorf("profile[python] = %q, want deep", profile["python"])
	}
	if profile["javascript"] != "deep" {
		t.Errorf("profile[javascript] = %q, want deep", profile["javascript"])
	}
	// Explicit override wins.
	if profile["go"] != "off" {
		t.Errorf("profile[go] = %q, want off", profile["go"])
	}
	// An explicitly configured language with no extension mapping is still
	// recorded so the audit trail is complete.
	if profile["terraform"] != "standard" {
		t.Errorf("profile[terraform] = %q, want standard", profile["terraform"])
	}
}

func TestFilterArtifactsByLanguageProfile(t *testing.T) {
	t.Parallel()

	artifacts := []discovery.Artifact{
		{Path: "main.go", Type: discovery.Source},
		{Path: "app.py", Type: discovery.Source},
		{Path: "index.ts", Type: discovery.Source},
		{Path: "config.yaml", Type: discovery.Config},           // no source language
		{Path: "package-lock.json", Type: discovery.Lockfile},   // deps must still scan
		{Path: "prompts/agent.md", Type: discovery.AIComponent}, // AI must still scan
		{Path: "query.sql", Type: discovery.Source},             // unknown source language
	}

	cfg := SASTConfig{Languages: map[string]string{
		"go":     "off",
		"python": "standard",
	}}

	got := FilterArtifactsByLanguageProfile(artifacts, cfg)

	var gotPaths []string
	for _, a := range got {
		gotPaths = append(gotPaths, a.Path)
	}

	// main.go dropped (go=off); everything else survives.
	want := []string{"app.py", "index.ts", "config.yaml", "package-lock.json", "prompts/agent.md", "query.sql"}
	if len(gotPaths) != len(want) {
		t.Fatalf("filtered paths = %v, want %v", gotPaths, want)
	}
	for i := range want {
		if gotPaths[i] != want[i] {
			t.Errorf("filtered[%d] = %q, want %q (order must be preserved)", i, gotPaths[i], want[i])
		}
	}
}

func TestFilterArtifactsByLanguageProfile_NoOffLanguages(t *testing.T) {
	t.Parallel()

	artifacts := []discovery.Artifact{
		{Path: "main.go", Type: discovery.Source},
		{Path: "app.py", Type: discovery.Source},
	}
	// Default profile turns nothing off, so nothing is filtered.
	got := FilterArtifactsByLanguageProfile(artifacts, SASTConfig{})
	if len(got) != len(artifacts) {
		t.Errorf("filtered %d artifacts with default profile, want %d (no drops)", len(got), len(artifacts))
	}
}

func TestLoadScanConfig_SASTLanguages(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	content := `scan:
  sast:
    languages:
      python: deep
      javascript: deep
      typescript: deep
      go: standard
      rust: off
`
	if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadScanConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := cfg.Scan.SAST.ResolveDepth("python"); got != SASTDeep {
		t.Errorf("python depth = %q, want deep", got)
	}
	if got := cfg.Scan.SAST.ResolveDepth("go"); got != SASTStandard {
		t.Errorf("go depth = %q, want standard", got)
	}
	if got := cfg.Scan.SAST.ResolveDepth("rust"); got != SASTOff {
		t.Errorf("rust depth = %q, want off", got)
	}
	// A language absent from config still gets its default.
	if got := cfg.Scan.SAST.ResolveDepth("ruby"); got != SASTStandard {
		t.Errorf("ruby depth = %q, want standard (default)", got)
	}

	if err := cfg.Scan.SAST.Validate(); err != nil {
		t.Errorf("Validate() on parsed config = %v, want nil", err)
	}
}

func TestLoadScanConfig_SASTLanguages_Absent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	content := `scan:
  exclude:
    - "vendor/"
`
	if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadScanConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Scan.SAST.Languages != nil {
		t.Errorf("expected nil Languages when sast block absent, got %v", cfg.Scan.SAST.Languages)
	}
	// Defaults still apply through the nil config.
	if got := cfg.Scan.SAST.ResolveDepth("python"); got != SASTDeep {
		t.Errorf("python depth with no sast block = %q, want deep", got)
	}
}
