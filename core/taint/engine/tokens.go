package engine

import "sort"

// isIdentStart reports whether b can begin an identifier (letter or underscore;
// '$' allowed for JS).
func isIdentStart(b byte) bool {
	return b == '_' || b == '$' ||
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// isIdentPart reports whether b can continue an identifier.
func isIdentPart(b byte) bool {
	return isIdentStart(b) || (b >= '0' && b <= '9')
}

// isSimpleIdent reports whether s is a single bare identifier (no dots, no
// brackets, no whitespace) — the only assignment LHS shape we track.
func isSimpleIdent(s string) bool {
	if s == "" {
		return false
	}
	if !isIdentStart(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !isIdentPart(s[i]) {
			return false
		}
	}
	return !isKeyword(s)
}

// isKeyword reports whether s is a language keyword that must never be treated
// as a variable name (covers both Python and JS; a superset is harmless here).
func isKeyword(s string) bool {
	switch s {
	case "if", "elif", "else", "for", "while", "return", "yield", "def",
		"class", "import", "from", "as", "with", "try", "except", "finally",
		"raise", "pass", "break", "continue", "and", "or", "not", "in", "is",
		"lambda", "global", "nonlocal", "assert", "del", "async", "await",
		"True", "False", "None", "const", "let", "var", "function", "new",
		"typeof", "instanceof", "true", "false", "null", "undefined", "this",
		// Ruby keywords (superset; harmless — not valid identifiers, or already
		// covered above / in the Rust/C# sets below: do, case, self, super).
		"end", "then", "begin", "ensure", "rescue", "when", "unless", "until",
		"elsif", "nil", "module", "next", "redo", "retry", "__FILE__", "__LINE__",
		// Rust keywords (superset is harmless: these are never variable names).
		// `let`, `as`, `None` are already covered by the Python/JS set above.
		"mut", "fn", "match", "loop", "move", "ref", "impl", "trait",
		"struct", "enum", "mod", "pub", "use", "crate", "self", "super", "where",
		"unsafe", "extern", "dyn", "type", "static", "Ok", "Err", "Some",
		// C# keywords/modifiers and common built-in type names that appear as bare
		// tokens in declarations and headers. Treating a type name as a
		// non-variable is safe: a type is never a taint-carrying value, so
		// excluding it only avoids a spurious "read" of a type name.
		"public", "private", "protected", "internal", "readonly",
		"using", "namespace", "void", "string", "int", "bool", "byte", "char",
		"long", "short", "double", "float", "decimal", "object", "string?",
		"switch", "case", "default", "throw", "catch", "foreach", "do",
		"override", "virtual", "abstract", "sealed", "partial",
		// Swift keywords/modifiers that appear as bare tokens in headers and
		// statements. `let`, `var`, `func`, `class`, `static`, `case`, `default`,
		// `do`, `nil`, `self`, `super`, `throw`, `enum`, `struct` are already
		// covered above; add the rest. Treating a keyword as a non-variable only
		// avoids a spurious read of it.
		"guard", "defer", "fileprivate", "open", "mutating", "nonmutating",
		"convenience", "required", "dynamic", "lazy", "weak", "unowned",
		"protocol", "extension", "typealias", "associatedtype", "inout",
		"some", "any", "throws", "rethrows", "willSet", "didSet", "get", "set",
		// Perl declaration/control keywords (superset is harmless: these are never
		// taint-carrying variable names). `my`/`our`/`local` are binding keywords;
		// `sub`/`package`/`qw`/`wantarray` must never be read as a variable.
		"my", "our", "local", "sub", "package", "qw", "wantarray",
		// Lua keywords (superset is harmless: these are never taint-carrying
		// variable names). `local`, `then`, `end`, `nil`, `until`, `not`, `and`,
		// `or`, `in`, `do`, `else`, `function` are already covered above; add the
		// rest.
		"elseif", "repeat", "goto",
		// Dart keywords/modifiers and common built-in type names that appear as
		// bare tokens in declarations and headers. `var`, `final`, `const`, `class`,
		// `if`, `for`, `while`, `return`, `void`, `int`, `bool`, `double`, `null`,
		// `true`, `false`, `this`, `super`, `new`, `try`, `catch`, `switch`, `case`,
		// `default`, `import`, `enum`, `throw`, `async`, `await`, `dynamic` (=type)
		// are already covered above. Add the Dart-specific rest; treating a keyword
		// or a type name as a non-variable only avoids a spurious read of it.
		// NOTE: Dart's CONTEXTUAL keywords (`on`, `library`, `part`, `show`, `hide`,
		// `num`) are deliberately NOT listed — they are built-in identifiers that are
		// valid variable/function names both in Dart and in every other language, so
		// putting them in this SHARED set silently suppresses real reads (a function
		// named `show`, a var named `on`) across all languages.
		"late", "factory", "extends", "implements", "mixin",
		"deferred", "covariant", "rethrow",
		"String", "List", "Map", "Set", "Future", "Stream", "Object",
		"Function", "Never", "Uri",
		// Elixir keywords/macros that appear as bare tokens in headers and blocks.
		// `def`/`fn`/`case`/`do`/`end`/`nil`/`true`/`false`/`for`/`with`/`import`/
		// `use`/`raise` are already covered above; add the rest.
		"defp", "defmodule", "defmacro", "defmacrop", "defstruct", "defprotocol",
		"defimpl", "cond", "receive", "after", "quote",
		"unquote", "alias", "require", "defdelegate", "defguard":
		return true
	}
	return false
}

// freeIdentifiers returns the bare variable names read in code: identifiers that
// are NOT the callee of a call (not immediately followed by `(`) and not a dotted
// attribute tail. This is what "reads a variable" means for propagation — a
// tainted var mentioned anywhere in an expression propagates. Deterministic and
// deduplicated.
func freeIdentifiers(_ langKind, code string) []string {
	seen := map[string]struct{}{}
	var out []string
	i := 0
	n := len(code)
	for i < n {
		if !isIdentStart(code[i]) {
			i++
			continue
		}
		start := i
		for i < n && isIdentPart(code[i]) {
			i++
		}
		name := code[start:i]
		// Skip a dotted attribute tail: if preceded by '.', it is an attribute,
		// not a free variable (the receiver at the head of a chain is still
		// recorded, which is harmless — a module name like `os` is never tainted,
		// and a real receiver like `q` in `q.strip()` correctly counts as a read).
		if start > 0 && code[start-1] == '.' {
			continue
		}
		if isKeyword(name) {
			continue
		}
		if _, dup := seen[name]; !dup {
			seen[name] = struct{}{}
			out = append(out, name)
		}
	}
	return out
}

// sortStrings sorts a string slice in place (stable, ascending) so statement
// reads and engine output are deterministic.
func sortStrings(s []string) {
	sort.Strings(s)
}
