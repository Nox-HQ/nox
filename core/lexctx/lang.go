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
//
// This package is the single source of truth for lexical context in Nox. No
// analyzer or matcher should reinvent "is this byte inside a comment, a string,
// or an encoded blob" with its own hand-rolled scanner — reach for Classify /
// KindAt / InCode / SuppressNonCode / InDataBlob (whole-file, offset-based) or
// HashCommentStart (a single line of a #-comment config format) instead. Four
// separate rule false-positive/false-negative bugs were all the same shape — a
// pattern trusted in a lexical context where it cannot mean what the rule
// assumed — and unifying that judgement here retires the whole class.
package lexctx

import (
	"path/filepath"
	"sort"
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
	LangCPP        // C/C++ — //, /*…*/, "…" (L/u8/u/U prefixes), R"(…)" raw, '…' (char), #… preprocessor, \ line-splice
	LangPerl       // Perl — #, POD =pod…=cut, "…"/'…', `…`, q()/qq()/qw()/qx(), heredocs, m//, s///
	LangScala      // Scala — //, NESTED /*…*/, "…", """…""" (raw multi-line), s"…"/f"…"/raw"…" interp, '…' (char) vs 'sym (Symbol)
	LangKotlin     // Kotlin — //, /**…*/, NESTED /*…*/, "…" ($var/${…} templates), """…""" (raw), '…' (char)
	LangShell      // Shell/Bash — # comments, '…' (literal), "…" ($var/$(…) interp), $'…' (ANSI-C), `…`, $(…), heredocs
	LangPowerShell // PowerShell — #, <#…#>, '…' (''-escaped), "…" ($var/$()/`-escaped), @"…"@ / @'…'@ here-strings
	LangSwift      // Swift — //, NESTED /*…*/, "…" (\(…) interp), """…""" (multiline), #"…"# / ##"…"## raw (\#(…) interp)
	LangObjC       // Objective-C — C lexing plus @"…" NSString literals; //, /*…*/, "…", 'c', #… preprocessor, \ line-splice
	LangLua        // Lua — -- line comments, --[[…]] / --[==[…]==] long-bracket block comments, "…"/'…' strings, [[…]] / [==[…]==] long strings (no escapes)
	LangDart       // Dart — //, ///, NESTED /*…*/, '…'/"…" ($var/${…} interp), '''…'''/"""…""" (multiline), r'…'/r"…" raw (no interp)
	LangElixir     // Elixir — # comments (no block comments), "…" (#{…} interp), '…' charlist, """…"""/'''…''' heredocs, ~s()/~r()/~w() sigils, ?c char code
	LangClojure    // Clojure — ; comments, "…" (Java escapes), #"…" regex, \c char literals; s-expression Lisp
	LangGroovy     // Groovy — //, /*…*/ (non-nesting), "…" ($var/${…} GString), '…' (plain), """…"""/'''…''' (multiline), /…/ slashy (regex), $/…/$ dollar-slashy
	LangYAML       // YAML / GitHub Actions workflows — # line comments, '…' / "…" quoted scalars
	LangDockerfile // Dockerfile / Containerfile — # line comments, '…' / "…" quoted arguments
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
	case LangCPP:
		return "cpp"
	case LangPerl:
		return "perl"
	case LangScala:
		return "scala"
	case LangKotlin:
		return "kotlin"
	case LangShell:
		return "shell"
	case LangPowerShell:
		return "powershell"
	case LangSwift:
		return "swift"
	case LangObjC:
		return "objc"
	case LangLua:
		return "lua"
	case LangDart:
		return "dart"
	case LangElixir:
		return "elixir"
	case LangClojure:
		return "clojure"
	case LangGroovy:
		return "groovy"
	case LangYAML:
		return "yaml"
	case LangDockerfile:
		return "dockerfile"
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
	// C and C++ share comment/string lexing and dangerous-API surface, so one
	// lexer serves every dialect extension. Headers (.h/.hpp/.hh/.hxx) carry the
	// same code as their translation units.
	".c":     LangCPP,
	".h":     LangCPP,
	".cc":    LangCPP,
	".cpp":   LangCPP,
	".cxx":   LangCPP,
	".c++":   LangCPP,
	".hpp":   LangCPP,
	".hh":    LangCPP,
	".hxx":   LangCPP,
	".ipp":   LangCPP,
	".inl":   LangCPP,
	".pl":    LangPerl,
	".pm":    LangPerl,
	".cgi":   LangPerl,
	".t":     LangPerl,
	".scala": LangScala,
	".sc":    LangScala,
	".kt":    LangKotlin,
	".kts":   LangKotlin,
	".sh":    LangShell,
	".bash":  LangShell,
	".ps1":   LangPowerShell,
	".psm1":  LangPowerShell,
	".psd1":  LangPowerShell,
	".swift": LangSwift,
	// Objective-C / Objective-C++ translation units. Only `.m` and `.mm` map to
	// LangObjC — a `.h` header is shared C/C++/ObjC surface and stays LangCPP
	// (mapped above) so the C/C++ lexer keeps owning it; overriding `.h` here
	// would clobber every C and C++ header. ObjC lexing is C plus `@"…"` NSString
	// literals, so the C-derived scanner handles a `.h` acceptably either way, but
	// the conservative choice is to leave headers with the incumbent C/C++ lexer.
	".m":      LangObjC,
	".mm":     LangObjC,
	".lua":    LangLua,
	".dart":   LangDart,
	".ex":     LangElixir,
	".exs":    LangElixir,
	".clj":    LangClojure,
	".cljs":   LangClojure,
	".cljc":   LangClojure,
	".edn":    LangClojure,
	".groovy": LangGroovy,
	".gradle": LangGroovy,
}

// filenameToLang maps well-known extension-less Ruby filenames to LangRuby.
// Gemfile / Rakefile carry Ruby code but have no `.rb` extension, so an
// extension-only lookup misses them; LangFromPath consults this by base name.
var filenameToLang = map[string]Lang{
	"Gemfile":     LangRuby,
	"Rakefile":    LangRuby,
	"Jenkinsfile": LangGroovy,
}

// SourceExtensions returns every file extension the lexer recognises as source
// code (each including the leading dot), sorted. It is the canonical set of
// "code we can lex", so a consumer like the file discoverer can derive its own
// source predicate from it instead of maintaining a second, drift-prone list.
// YAML and Dockerfile are deliberately absent (see the note above extToLang).
func SourceExtensions() []string {
	out := make([]string, 0, len(extToLang))
	for ext := range extToLang {
		out = append(out, ext)
	}
	sort.Strings(out)
	return out
}

// LangFromPath infers the language from a file path's extension. Detection is
// extension-only on purpose: it is deterministic, offline, and cheap, and a
// wrong guess only costs us the FP-suppression benefit for that file (never
// correctness) because the scanner degrades to a single code region.
//
// Note: LangYAML and LangDockerfile are deliberately NOT mapped here. They are
// reachable via Classify (and the absence matcher's HashCommentStart), but the
// secrets, taint, ai, and agentflow analyzers all gate on LangFromPath, so
// mapping .yml/.yaml/Dockerfile would silently change their behavior on every
// such file. That is a separate, larger decision; the comment-context
// unification keeps LangFromPath's answers unchanged.
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
