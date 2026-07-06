package lexctx

// scanObjC walks Objective-C (and Objective-C++) source and classifies each byte
// as code, string, or comment. Objective-C's lexical grammar is C with one extra
// string form, so this scanner reuses the C/C++ helpers (comments, C strings,
// char literals, preprocessor directives, line-splice) and adds the ONE ObjC
// gotcha a plain C scanner gets wrong:
//
//   - `@"..."` NSString literals. The `@` is an ObjC literal marker; the string
//     body that follows uses the SAME backslash-escape rules as a C string
//     (`\"`, `\\`), so a URL's `//` or a base64 blob inside an NSString never
//     begins a comment and never leaks into code. Both the `@` and the quoted
//     body are emitted as one STRING region so a match anywhere in the literal is
//     gated exactly like a plain C string literal. (Only `@"..."` is a string
//     literal — `@'...'` is not valid ObjC, and `@[...]` / `@{...}` /
//     `@(expr)` are array/dictionary/boxed-expression literals whose bodies are
//     real CODE, so the `@` there is left as an ordinary code byte.)
//
// Everything else mirrors scanCPP (Objective-C++ `.mm` files embed C++), so the
// shared helpers carry:
//
//   - `//` line comments (honoring a `\`-newline splice) and `/* ... */` block
//     comments (which do NOT nest in C/ObjC — the FIRST `*/` closes).
//   - C string literals `"..."` and char literals `'c'` / `'\n'` with escapes; a
//     digit-separator apostrophe is disambiguated the same way as C++.
//   - preprocessor directives (`#import <Foundation/Foundation.h>`,
//     `#define X 1`), whose `#import`/`#include` angle header name is a string
//     span so its `/` and `.` never begin a comment, and which honor `\`-newline
//     splicing.
//
// Like the other scanners it emits strictly increasing, contiguous spans into a
// regionBuilder so the returned regions are gap-free and cover [0, len(content)).
func scanObjC(content []byte) []Region {
	var b regionBuilder
	i := 0
	n := len(content)
	atLineStart := true // true at the first non-blank byte of a logical line
	for i < n {
		c := content[i]
		switch {
		case c == '/' && i+1 < n && content[i+1] == '/':
			end := scanCPPLineComment(content, i)
			b.emit(i, end, KindComment)
			i = end
			atLineStart = false
		case c == '/' && i+1 < n && content[i+1] == '*':
			end := scanBlockComment(content, i+2)
			b.emit(i, end, KindComment)
			i = end
			atLineStart = false
		case c == '#' && atLineStart:
			// A preprocessor directive. Scan the (possibly line-spliced) directive,
			// classifying an `#import`/`#include <...>` header name as a string; the
			// shared C/C++ scanner already treats `#import` like `#include`.
			i = scanCPPPreprocessor(content, i, &b)
			atLineStart = false
		case c == '@' && i+1 < n && content[i+1] == '"':
			// An `@"..."` NSString literal: emit the `@` and the quoted body as one
			// string region. The body follows C escape rules, so scanCPPString handles
			// it; we start the string span at the `@` so the whole literal is string.
			end := scanCPPString(content, i+1, 0)
			b.emit(i, end, KindString)
			i = end
			atLineStart = false
		case c == '"':
			end := scanCPPString(content, i, 0)
			b.emit(i, end, KindString)
			i = end
			atLineStart = false
		case c == '\'' && cppCharLiteralHere(content, i):
			end := scanCPPChar(content, i)
			b.emit(i, end, KindString)
			i = end
			atLineStart = false
		case c == '\n':
			b.emit(i, i+1, KindCode)
			i++
			atLineStart = true
		case c == ' ' || c == '\t' || c == '\r':
			b.emit(i, i+1, KindCode)
			i++
			// Leading whitespace does not end line-start: `  #define` is a directive.
		default:
			b.emit(i, i+1, KindCode)
			i++
			atLineStart = false
		}
	}
	return b.finish(n)
}
