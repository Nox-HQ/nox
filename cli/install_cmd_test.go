package main

import "testing"

func TestParseRegistryRef_BareURL(t *testing.T) {
	src := parseRegistryRef("https://example.com/nox/index.json")
	if src.URL != "https://example.com/nox/index.json" {
		t.Errorf("URL: got %q", src.URL)
	}
	if src.Name != "example.com" {
		t.Errorf("Name: got %q, want example.com", src.Name)
	}
}

func TestParseRegistryRef_NameAndURL(t *testing.T) {
	src := parseRegistryRef("acme=https://acme.internal/nox/index.json")
	if src.Name != "acme" {
		t.Errorf("Name: got %q", src.Name)
	}
	if src.URL != "https://acme.internal/nox/index.json" {
		t.Errorf("URL: got %q", src.URL)
	}
}

func TestParseRegistryRef_Empty(t *testing.T) {
	if got := parseRegistryRef(""); got.URL != "" {
		t.Errorf("expected empty source, got %+v", got)
	}
}
