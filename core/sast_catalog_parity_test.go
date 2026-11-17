package core

import (
	"testing"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/taint"
)

// meta.sast_languages is the record of which languages a scan analysed. It was
// hand-listed, and Scala, Elixir and Dart (each with a taint catalog) were
// missing from it, so a report said nothing about them and a
// `scan.sast.languages: {dart: off}` config silently did nothing. These tests
// tie the list to the engine's own inventory so it cannot drift again.

// A language with a taint catalog must appear in the resolved profile.
func TestProfileCoversEveryTaintCatalogLanguage(t *testing.T) {
	profile := SASTConfig{}.ResolvedProfile()
	for _, lang := range taint.MustDefault().Languages() {
		if _, ok := profile[lang]; !ok {
			t.Errorf("taint catalog has language %q but meta.sast_languages omits it; add its extensions to extensionLanguages", lang)
		}
	}
}

// Every extension the lexer reads as source must resolve to a language, and to
// the name the lexer gives it (typescript and c are the two finer splits core
// makes of the lexer's javascript and cpp).
func TestExtensionLanguagesCoverEverySourceExtension(t *testing.T) {
	finer := map[string]string{"typescript": "javascript", "c": "cpp"}
	for _, ext := range lexctx.SourceExtensions() {
		got := LanguageForExtension("x" + ext)
		if got == "" {
			t.Errorf("source extension %q maps to no SAST language", ext)
			continue
		}
		want := lexctx.LangFromPath("x" + ext).String()
		if lex, ok := finer[got]; ok {
			got = lex
		}
		if got != want {
			t.Errorf("extension %q: core language %q, lexer language %q", ext, got, want)
		}
	}
}

// Switching a language off must reach the languages that were missing.
func TestSASTOffReachesCatalogLanguages(t *testing.T) {
	cfg := SASTConfig{Languages: map[string]string{"dart": "off", "scala": "off", "elixir": "off"}}
	var in []discovery.Artifact
	for _, p := range []string{"a.dart", "b.scala", "c.ex", "d.go"} {
		in = append(in, discovery.Artifact{Path: p, Type: discovery.Source})
	}
	out := FilterArtifactsByLanguageProfile(in, cfg)
	if len(out) != 1 || out[0].Path != "d.go" {
		t.Errorf("after turning dart/scala/elixir off, kept %v, want only d.go", out)
	}
}
