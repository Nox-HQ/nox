// Package engine turns source files into taint Units and runs a deterministic,
// intraprocedural, argument-aware taint analysis over them. It is the first real
// dataflow layer above the core/taint catalog foundation: where the catalog
// answers "is this call a source/sink/sanitizer", this package answers "does an
// untrusted value actually reach a dangerous call in this function".
//
// WHY a line/statement recognizer rather than a full parser: Nox ships a single
// static pure-Go binary with no CGo and no heavy parser dependency. A full
// Python/JS grammar (tree-sitter et al.) is CGo or a large pure-Go port — a cost
// the project deliberately refuses. Instead we lean on core/lexctx to see only
// real CODE (never strings/comments) and recognize the two statement shapes that
// carry the overwhelming majority of injection bugs: an assignment `lhs = expr`
// and a bare call `callee(args)`. This is intraprocedural and straight-line by
// construction; its limits are documented on StructuralEngine and are exactly
// the boundary where the cross-file taint-analysis plugin takes over.
package engine

import (
	"strings"

	"github.com/nox-hq/nox/core/lexctx"
)

// unitDraft is the extractor's internal, pre-catalog view of one analyzable
// scope (a function body or the module top level). It is converted to a
// taint.Unit at the analyzer boundary. Kept unexported so the extractor's shape
// stays an implementation detail of this package.
type unitDraft struct {
	funcName string
	// params are the positional parameter names of the function, in declaration
	// order. Empty for the module unit. Used by the interprocedural summary pass
	// to map a caller argument position to the callee parameter it binds.
	params []string
	stmts  []stmtDraft
}

// stmtDraft is one recognized simple statement: either an assignment or a bare
// call. It mirrors taint.Statement but stays internal so extraction can evolve
// without touching the foundation's contract.
type stmtDraft struct {
	line    int
	assigns string
	calls   []string
	reads   []string
	// chains are the dotted attribute/identifier chains read on the RHS,
	// whether or not followed by a call (e.g. "request.args", "req.query"). They
	// let the engine recognize source ATTRIBUTES (request.args) alongside source
	// CALLS (request.args.get) — many web sources are attribute accesses, not
	// calls.
	chains   []string
	sinkArgs map[string]sinkArgDraft
	// returns are the variable names returned by a `return x` / `return a, b`
	// statement. Empty for non-return statements. The interprocedural summary
	// pass uses it to decide whether a parameter reaches the function's return.
	returns []string
}

// sinkArgDraft is the internal form of taint.SinkArgInfo (see there for the
// per-field semantics). It records the argument-shape evidence gathered at a
// sink call site so the engine can apply the catalog's argument notes.
type sinkArgDraft struct {
	taintedArgVars  []string
	argCount        int
	shellTrue       bool
	firstArgTainted bool
	// positionalVars lists, per positional argument slot, the variable names in
	// that slot (index 0 = first positional). Used by the interprocedural pass to
	// bind a caller argument position to a callee parameter index.
	positionalVars [][]string
	// positionalArgs lists, per positional argument slot (index-aligned with
	// positionalVars), the code-view text of that slot. It lets the engine spot a
	// SOURCE used directly as a sink argument (sink(source())), which binds no
	// variable and is otherwise invisible to variable propagation.
	positionalArgs []string
	// promptRoles maps a variable appearing inside a chat/LLM prompt argument to the
	// chat role of the message it lands in (see taint.SinkArgInfo.PromptRoles). Only
	// populated for Python chat-message-shaped calls; nil otherwise.
	promptRoles map[string]string
	// promptStaticSystem records that the call carries a static (untainted) system
	// message — the data boundary that makes user-role untrusted content the safe
	// pattern (see taint.SinkArgInfo.PromptHasStaticSystem).
	promptStaticSystem bool
}

// extractUnits parses content into unit drafts for the given language. It walks
// only the code regions reported by lexctx, segments them into logical lines
// (joining bracket/paren continuations), and recognizes assignments and calls.
// Deterministic: same bytes in, same units out, in source order.
func extractUnits(lang lexctx.Lang, content []byte) []unitDraft {
	regions := lexctx.Classify(lang, content)

	switch lang {
	case lexctx.LangPython:
		return extractPython(logicalLines(content, regions, false))
	case lexctx.LangJavaScript:
		// JS statements are `;`-terminated and brace-delimited; only paren/array
		// continuations should merge physical lines, and each logical line is
		// then split on top-level semicolons into separate statements.
		return extractJavaScript(splitSemicolons(logicalLines(content, regions, true)))
	case lexctx.LangGo:
		// Go gets an AST-precise extractor (go/parser) rather than the lexctx line
		// recognizer: nox is itself Go, so the pure-Go stdlib parser is free,
		// precise, and deterministic. See extract_go.go / docs/design/go-taint.md.
		return extractGo(content)
	case lexctx.LangPHP:
		// PHP uses the line/statement recognizer like Python/JS: statements are
		// `;`-terminated and bodies are brace-delimited, so paren/array
		// continuations merge physical lines and each logical line is split on
		// top-level semicolons. lexctx has already blanked the HTML template shell
		// (non-code), so only real <?php … ?> code reaches the recognizer.
		return extractPHP(splitSemicolons(logicalLines(content, regions, true)))
	case lexctx.LangJava:
		// Java uses the lexctx line/statement recognizer (no CGo tree-sitter): it is
		// brace-delimited and `;`-terminated like JS, so it shares the
		// logicalLines/splitSemicolons segmentation. See extract_java.go.
		return extractJava(splitSemicolons(logicalLines(content, regions, true)))
	case lexctx.LangRuby:
		// Ruby uses the lexctx line/statement recognizer like Python. Its `{}` are
		// block/hash delimiters (not statement bodies — those are `def...end`), so
		// braces must NOT force line-merging, matching the JS convention. Ruby
		// statements are newline-terminated, so no semicolon split is needed.
		return extractRuby(logicalLines(content, regions, true))
	case lexctx.LangRust:
		// Rust uses the line/statement RECOGNIZER (like Python/JS, NOT a real
		// parser — only Go gets go/ast). Braces delimit blocks (so a function body
		// is not collapsed into one logical line) and statements are `;`-terminated,
		// so — like JS — only paren/bracket continuations merge physical lines and
		// each logical line is split on top-level semicolons. Ownership, Result/`?`
		// unwrapping, iterator chains, and macro sinks make line recognition coarse;
		// see extract_rust.go for the honest limits.
		return extractRust(splitSemicolons(logicalLines(content, regions, true)))
	case lexctx.LangCSharp:
		// C# is brace-delimited like JS: paren/array continuations merge physical
		// lines, then each logical line splits on top-level semicolons into
		// statements. Unlike JS it recognizes method headers for per-method units.
		return extractCSharp(splitSemicolons(logicalLines(content, regions, true)))
	case lexctx.LangCPP:
		// C/C++ is brace-delimited and `;`-terminated like C#: paren/array
		// continuations merge physical lines, then each logical line splits on
		// top-level semicolons into statements. Function definitions are recognized
		// for per-function units (with params), and `::` is normalized to `.` inside
		// extractCPP so scope-resolved calls match the catalog. See extract_cpp.go.
		return extractCPP(splitSemicolons(logicalLines(content, regions, true)))
	case lexctx.LangPerl:
		// Perl uses the line/statement RECOGNIZER (no CGo interpreter). Statements
		// are `;`-terminated and sub bodies are brace-delimited, so — like PHP/JS —
		// only paren/bracket continuations merge physical lines and each logical
		// line is split on top-level semicolons. Perl's dynamic dispatch, sigil
		// magic, and context-sensitive syntax make line recognition coarse; see
		// extract_perl.go for the honest limits (recall is moderate by design).
		return extractPerl(splitSemicolons(logicalLines(content, regions, true)))
	case lexctx.LangScala:
		// Scala is brace-delimited like Java/C#: braces delimit blocks (so a method
		// body is not collapsed into one logical line) and paren/bracket
		// continuations merge physical lines. Statements are newline-terminated but
		// a `;` may pack several onto one line, so — like Java — each logical line is
		// split on top-level semicolons. It recognizes `def` headers for per-method
		// units. See extract_scala.go.
		return extractScala(splitSemicolons(logicalLines(content, regions, true)))
	case lexctx.LangKotlin:
		// Kotlin is brace-delimited like Java/JS: paren/array continuations merge
		// physical lines, then each logical line splits on top-level semicolons.
		// Kotlin statements are usually newline-terminated (semicolons optional),
		// so the split only affects the rare `a; b` line; it recognizes `fun`
		// headers for per-function units. See extract_kotlin.go.
		return extractKotlin(splitSemicolons(logicalLines(content, regions, true)))
	case lexctx.LangShell:
		// Shell is command-oriented and paren-less. Statements are newline- or
		// `;`-terminated; `{}`/`()` delimit function bodies (not continuations), so
		// braces are treated as blocks (like Ruby). A dedicated recognizer handles
		// shell's `var=value` assignments and space-separated command calls — the
		// shared paren/comma recognizer does not fit shell syntax. See
		// extract_shell.go for the honest limits (recall is the lowest of any
		// language: word-splitting and dynamic constructs a flat recognizer cannot
		// follow).
		return extractShell(splitSemicolons(logicalLines(content, regions, true)))
	case lexctx.LangPowerShell:
		// PowerShell uses the line/statement RECOGNIZER (no CGo parser). Statements
		// are newline-terminated (like Ruby/Python), and `{}` delimit script blocks
		// and function bodies — so braces must NOT force line-merging (a function
		// body would collapse into one logical line); only paren/bracket
		// continuations merge physical lines. A semicolon can separate statements on
		// one line, so the logical lines are also split on top-level semicolons.
		return extractPowerShell(splitSemicolons(logicalLines(content, regions, true)))
	case lexctx.LangSwift:
		// Swift is brace-delimited like C#/JS: paren/array continuations merge
		// physical lines, then each logical line splits on top-level semicolons.
		// Like C# it recognizes `func` headers for per-function units (and their
		// internal parameter binding names). See extract_swift.go.
		return extractSwift(splitSemicolons(logicalLines(content, regions, true)))
	case lexctx.LangObjC:
		// Objective-C is C at its core: brace-delimited and `;`-terminated, so —
		// like C/C++ — paren/array continuations merge physical lines and each
		// logical line splits on top-level semicolons. The extractor rewrites bracket
		// message sends `[recv sel:arg]` to dotted calls `recv.sel(arg)` before the
		// shared recognizer, and recognizes both C function and ObjC method
		// definitions for per-scope units. See extract_objc.go.
		return extractObjC(splitSemicolons(logicalLines(content, regions, true)))
	case lexctx.LangLua:
		// Lua uses the line/statement RECOGNIZER (no CGo interpreter). `{}` are
		// table constructors, NOT statement bodies — function/if/for bodies are
		// delimited by keywords and closed by `end` — so braces must NOT force
		// line-merging (a function body would collapse into one logical line);
		// only paren/bracket continuations merge physical lines. Statements are
		// newline-terminated, but a `;` may separate several on one line, so the
		// logical lines are also split on top-level semicolons. A per-line
		// normalization rewrites the `obj:method()` method-call colon to `.` so
		// the shared recognizer and catalog suffix-matching see `obj.method`.
		return extractLua(splitSemicolons(logicalLines(content, regions, true)))
	case lexctx.LangClojure:
		// Clojure is a Lisp: prefix s-expressions `(fn arg …)`, `(def x v)`,
		// `(let [x v] …)` — very different from the assignment/call line model the
		// shared recognizer assumes. A dedicated paren-aware FORM recognizer walks
		// the code-only byte stream (strings/comments already blanked by lexctx) and
		// emits the shared unitDraft IR: `(def NAME expr)` / `(let [NAME expr …])`
		// bindings and `(CALLEE args…)` calls. Recall is the LOWEST of any language
		// by design — threading macros, HOFs, and destructuring are beyond a form
		// recognizer; see extract_clojure.go for the honest limits.
		return extractClojure(content, regions)
	case lexctx.LangElixir:
		// Elixir uses the line/statement RECOGNIZER (no CGo parser). Scoping is by
		// `def`/`defp ... do ... end` (like Ruby's `def...end`), so `{}` are map/
		// struct/binary delimiters — NOT statement bodies — and must NOT force
		// line-merging; only paren/bracket continuations merge physical lines.
		// Statements are newline-terminated, and a `;` can pack several onto one
		// line, so the logical lines are also split on top-level semicolons. The
		// pipe operator `|>` and pattern-matching make recall lower (documented in
		// extract_elixir.go and testdata/precision-suite-elixir/README.md).
		return extractElixir(splitSemicolons(logicalLines(content, regions, true)))
	case lexctx.LangDart:
		// Dart is brace-delimited like Java/Kotlin: paren/array continuations merge
		// physical lines, then each logical line splits on top-level semicolons.
		// Dart statements are `;`-terminated and method/function bodies are
		// brace-delimited, so it recognizes headers for per-function units (with
		// params). See extract_dart.go.
		return extractDart(splitSemicolons(logicalLines(content, regions, true)))
	case lexctx.LangGroovy:
		// Groovy is brace-delimited like Java/Kotlin/Groovy-on-the-JVM: paren/array
		// continuations merge physical lines, then each logical line splits on
		// top-level semicolons. Groovy statements are usually newline-terminated
		// (semicolons optional), so the split only affects the rare `a; b` line; it
		// recognizes `def`/typed method headers for per-method units. See
		// extract_groovy.go.
		return extractGroovy(splitSemicolons(logicalLines(content, regions, true)))
	default:
		return nil
	}
}

// logicalLine is a source line paired with the code-only text used for
// recognition. Text has strings and comments blanked to spaces so token
// scanning never trips on an operator or paren that lives inside a literal,
// while byte offsets (and therefore the 1-based line number) stay aligned.
type logicalLine struct {
	line int    // 1-based line number where this logical line starts
	code string // code-only text of the logical line (literals blanked)
	raw  string // original text (used to read variable names verbatim)
}

// logicalLines splits content into logical lines: physical lines merged while
// brackets/parens/braces are unbalanced (so a multi-line call is one unit) and
// while a line ends in a backslash continuation. The code view blanks every
// non-code byte to a space, preserving offsets so a call spanning a string is
// still recognized by its code parentheses.
func logicalLines(content []byte, regions []lexctx.Region, bracesAreBlocks bool) []logicalLine {
	// codeMask is content with non-code bytes replaced by spaces (newlines kept
	// so line counting stays correct).
	codeMask := make([]byte, len(content))
	for i := range content {
		if content[i] == '\n' {
			codeMask[i] = '\n'
			continue
		}
		if lexctx.KindAt(regions, i) == lexctx.KindCode {
			codeMask[i] = content[i]
		} else {
			codeMask[i] = ' '
		}
	}

	var out []logicalLine
	lineNo := 1
	depth := 0
	var codeBuf, rawBuf strings.Builder
	startLine := 1
	flush := func() {
		if strings.TrimSpace(codeBuf.String()) != "" || strings.TrimSpace(rawBuf.String()) != "" {
			out = append(out, logicalLine{line: startLine, code: codeBuf.String(), raw: rawBuf.String()})
		}
		codeBuf.Reset()
		rawBuf.Reset()
	}

	i := 0
	n := len(content)
	lineStart := true
	for i < n {
		// Read one physical line [i, eol).
		eol := i
		for eol < n && content[eol] != '\n' {
			eol++
		}
		codeSeg := string(codeMask[i:eol])
		rawSeg := string(content[i:eol])
		if lineStart {
			startLine = lineNo
		}
		codeBuf.WriteString(codeSeg)
		rawBuf.WriteString(rawSeg)

		depth += bracketDelta(codeSeg, bracesAreBlocks)
		backslashCont := strings.HasSuffix(strings.TrimRight(codeSeg, " \t"), "\\")

		if depth <= 0 && !backslashCont {
			flush()
			depth = 0
			lineStart = true
		} else {
			// Continue onto next physical line; add a space so tokens don't glue.
			codeBuf.WriteByte(' ')
			rawBuf.WriteByte(' ')
			lineStart = false
		}

		i = eol + 1
		lineNo++
	}
	flush()
	return out
}

// bracketDelta returns the net change in continuation-bracket depth for a code
// segment. Parens and square brackets always count (a call or list spanning
// lines is one logical line). Braces count only when bracesAreBlocks is false
// (Python dict/set literals); for languages where `{}` delimits blocks and
// object literals (JS), braces must NOT force line merging or an entire function
// body would collapse into one logical line. Literals are already blanked, so
// every bracket here is real code.
func bracketDelta(code string, bracesAreBlocks bool) int {
	d := 0
	for i := 0; i < len(code); i++ {
		switch code[i] {
		case '(', '[':
			d++
		case ')', ']':
			d--
		case '{':
			if !bracesAreBlocks {
				d++
			}
		case '}':
			if !bracesAreBlocks {
				d--
			}
		}
	}
	return d
}

// splitSemicolons splits each logical line on top-level (non-bracketed)
// semicolons into separate logical lines, preserving the starting line number.
// JS packs multiple statements per line (`const x = a; foo(x);`) and this makes
// each its own recognizable statement. The code and raw views stay aligned
// because both are sliced at the same offsets.
func splitSemicolons(lines []logicalLine) []logicalLine {
	var out []logicalLine
	for _, ll := range lines {
		depth := 0
		start := 0
		emit := func(end int) {
			codeSeg := ll.code[start:end]
			rawSeg := ll.raw[start:end]
			if strings.TrimSpace(codeSeg) != "" || strings.TrimSpace(rawSeg) != "" {
				out = append(out, logicalLine{line: ll.line, code: codeSeg, raw: rawSeg})
			}
		}
		aligned := len(ll.code) == len(ll.raw)
		for i := 0; i < len(ll.code); i++ {
			switch ll.code[i] {
			case '(', '[', '{':
				depth++
			case ')', ']', '}':
				depth--
			case ';':
				if depth == 0 && aligned {
					emit(i)
					start = i + 1
				}
			}
		}
		if aligned {
			emit(len(ll.code))
		} else {
			out = append(out, ll)
		}
	}
	return out
}
