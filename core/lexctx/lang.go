// Package lexctx provides a pure-Go "lexical context" classifier that labels
// byte ranges of a source file as code, string-literal, or comment. Nox's SAST
// analyzers match regexes against raw file TEXT, so a pattern fires equally
// whether it appears in a live code assignment, inside a base64 SVG blob, in a
// lockfile hash, or in a comment. The overwhelming majority of those matches
// are false positives: the pattern is not code, it is data or prose that merely
// looks like a secret.
//
// The fix is structural without paying for a full parser: hand-rolled scanners
// walk the byte stream and track whether the cursor is inside a string or a
// comment. Downstream analyzers can then drop any match whose span is not code.
//
// The package is deliberately dependency-free and CGo-free — Nox ships a single
// static binary, and every classifier here degrades gracefully: an unknown
// language yields one big code region, so gating on lexctx is never worse than
// today's behavior (it only ever removes matches that are provably non-code).
package lexctx

import (
	"path/filepath"
	"strings"
)

// Lang identifies the source language whose lexical grammar drives scanning.
// Only the languages Nox's SAST rules actually target are enumerated; anything
// else maps to LangUnknown, which the scanner treats as one big code region.
type Lang int

// Supported languages. LangUnknown is the graceful-degrade sentinel.
const (
	LangUnknown Lang = iota
	LangPython
	LangJavaScript // JS, JSX, TS, TSX — they share comment/string/template lexing
	LangGo         // Go — //, /*…*/, "…", `…` (raw), '…' (rune)
	LangPHP        // PHP — <?php…?> islands; //,#,/*…*/, '…', "…", heredoc/nowdoc
	LangJava       // Java — //, /*…*/, /**…*/, "…", """…""" (text block), '…' (char)
	LangRuby       // Ruby — #, =begin/=end, '…', "…" (#{} interp), `…`, %w/%q, heredocs
	LangRust       // Rust — //,///,//!, NESTED /*…*/, "…", r#"…"#, b"…", '…' vs 'a lifetime
	LangCSharp     // C# — //, ///, /*…*/, "…", @"…" (verbatim), $"…" (interpolated), """…""" (raw), '…' (char)
)

// String returns a stable, lowercase label for the language. Used in metadata
// and test output; the exact spelling is part of the package's contract.
func (l Lang) String() string {
	switch l {
	case LangPython:
		return "python"
	case LangJavaScript:
		return "javascript"
	case LangGo:
		return "go"
	case LangPHP:
		return "php"
	case LangJava:
		return "java"
	case LangRuby:
		return "ruby"
	case LangRust:
		return "rust"
	case LangCSharp:
		return "csharp"
	default:
		return "unknown"
	}
}

// extToLang maps a lowercased file extension (including the dot) to a Lang.
// TypeScript and the JSX/TSX variants fold into LangJavaScript because their
// comment and string lexing is identical for our purposes — we only need to
// know "is this cursor inside code" and the grammars agree on that.
var extToLang = map[string]Lang{
	".py":      LangPython,
	".pyi":     LangPython,
	".pyw":     LangPython,
	".js":      LangJavaScript,
	".jsx":     LangJavaScript,
	".mjs":     LangJavaScript,
	".cjs":     LangJavaScript,
	".ts":      LangJavaScript,
	".tsx":     LangJavaScript,
	".mts":     LangJavaScript,
	".cts":     LangJavaScript,
	".go":      LangGo,
	".php":     LangPHP,
	".phtml":   LangPHP,
	".java":    LangJava,
	".rb":      LangRuby,
	".rake":    LangRuby,
	".gemspec": LangRuby,
	".rs":      LangRust,
	".cs":      LangCSharp,
}

// filenameToLang maps well-known extension-less Ruby filenames to LangRuby.
// Gemfile / Rakefile carry Ruby code but have no `.rb` extension, so an
// extension-only lookup misses them; LangFromPath consults this by base name.
var filenameToLang = map[string]Lang{
	"Gemfile":  LangRuby,
	"Rakefile": LangRuby,
}

// LangFromPath infers the language from a file path's extension. Detection is
// extension-only on purpose: it is deterministic, offline, and cheap, and a
// wrong guess only costs us the FP-suppression benefit for that file (never
// correctness) because the scanner degrades to a single code region.
func LangFromPath(path string) Lang {
	ext := strings.ToLower(filepath.Ext(path))
	if l, ok := extToLang[ext]; ok {
		return l
	}
	// Extension-less Ruby manifests (Gemfile, Rakefile) are matched by base name.
	if l, ok := filenameToLang[filepath.Base(path)]; ok {
		return l
	}
	return LangUnknown
}
