package deps

import (
	"testing"
)

func TestParseComposerLock(t *testing.T) {
	content := []byte(`{
		"packages": [
			{"name": "monolog/monolog", "version": "v2.9.1"},
			{"name": "symfony/console", "version": "v6.3.4"},
			{"name": "", "version": "1.0.0"}
		],
		"packages-dev": [
			{"name": "phpunit/phpunit", "version": "v10.4.1"},
			{"name": "symfony/console", "version": "v6.3.4"}
		]
	}`)

	pkgs, err := parseComposerLock(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages (deduped), got %d", len(pkgs))
	}

	// Check version stripping of v prefix.
	for _, p := range pkgs {
		if p.Ecosystem != "composer" {
			t.Errorf("expected ecosystem 'composer', got %q", p.Ecosystem)
		}
		if p.Version == "" || p.Version[0] == 'v' {
			t.Errorf("version should not have v prefix: %q", p.Version)
		}
	}

	// Check specific packages.
	foundMonolog := false
	foundPHPUnit := false
	for _, p := range pkgs {
		if p.Name == "monolog/monolog" && p.Version == "2.9.1" {
			foundMonolog = true
		}
		if p.Name == "phpunit/phpunit" && p.Version == "10.4.1" {
			foundPHPUnit = true
		}
	}
	if !foundMonolog {
		t.Error("monolog/monolog not found")
	}
	if !foundPHPUnit {
		t.Error("phpunit/phpunit not found")
	}
}

func TestParseComposerLock_Empty(t *testing.T) {
	content := []byte(`{"packages": [], "packages-dev": []}`)

	pkgs, err := parseComposerLock(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages, got %d", len(pkgs))
	}
}

func TestParseComposerLock_InvalidJSON(t *testing.T) {
	content := []byte(`{invalid}`)

	_, err := parseComposerLock(content)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}
