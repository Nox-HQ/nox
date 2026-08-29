package ai

import (
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
)

// maxLogCallScan bounds the search for the parenthesis closing a log call. A
// call whose arguments run longer than this is either machine-generated or
// unbalanced, and in both cases the scan gives up and the finding is kept:
// running off the end of a 2 MB file to decide one match is not worth it, and
// keeping is the safe direction.
const maxLogCallScan = 4096

// logsOnlyConstantText reports whether an AI-006 match is a log call that
// formats a constant sentence which merely contains the word "prompt" (or
// another of the rule's nouns), rather than one that logs a value.
//
// AI-006 is "prompt or LLM response logged without redaction", CWE-532. Its
// pattern anchors on a logging call and then accepts the noun anywhere in that
// call, including inside a string literal — and `print` in the call alternation
// also matches inside `Fprintf`. Nox's own CLI tripped the combination (#497):
//
//	fmt.Fprintf(os.Stderr, "this looks like CI, where nobody can approve a browser prompt.\n")
//
// which is a sentence about a *browser* prompt. The finding cannot be true
// there: a call whose arguments are all constants has no prompt to leak, so it
// is categorically wrong rather than merely low-value, and is dropped — the
// same shape as isSQLStatementExec for AI-049.
//
// The discriminator is where the value is, not what the sentence says. A leak
// needs something dynamic, and lexctx already knows which bytes of a call are
// code and which are constant text — including f-string and template-literal
// holes, which it classifies as code inside the surrounding string. So the
// match survives when either
//
//   - the matched noun is itself code (`fmt.Println(prompt)`,
//     `console.log(response.content)`), or
//   - code follows the noun inside the same call (`" + prompt)`, `{prompt}`,
//     `%s\n", userPrompt)`).
//
// Looking only after the noun is what makes the destination argument of the
// Fprint family — and any other bookkeeping argument that precedes the message,
// such as a log level — cost nothing: it sits before the sentence, so it is
// never mistaken for logged content, and no special case has to name it.
//
// A language lexctx cannot lex needs no branch of its own: Classify returns one
// all-code region for it, the noun then reads as code, and the match is kept.
// That is lexctx's graceful-degrade contract, and it means this filter can only
// ever remove matches whose text is provably constant.
func logsOnlyConstantText(lang lexctx.Lang, content []byte, f *findings.Finding) bool {
	start := lexctx.LineColToOffset(content, f.Location.StartLine, f.Location.StartColumn)
	end := lexctx.LineColToOffset(content, f.Location.EndLine, f.Location.EndColumn)
	if end <= start || end > len(content) {
		return false
	}

	regions := lexctx.Classify(lang, content)
	// The match ends on the last byte of the noun, so that byte's kind answers
	// "is the noun an identifier or is it text".
	if lexctx.KindAt(regions, end-1) == lexctx.KindCode {
		return false
	}

	open := codeIndexOfByte(regions, content, start, end, '(')
	if open < 0 {
		return false // no call opener in the match: not our shape, keep it
	}
	closing := matchingCloseParen(regions, content, open)
	if closing < 0 || closing <= end {
		return false
	}
	return !hasCodeWordByte(regions, content, end, closing)
}

// codeIndexOfByte returns the offset of the first occurrence of b in
// content[from:to) that lies in a code region, or -1.
func codeIndexOfByte(regions []lexctx.Region, content []byte, from, to int, b byte) int {
	for i := from; i < to; i++ {
		if content[i] == b && lexctx.KindAt(regions, i) == lexctx.KindCode {
			return i
		}
	}
	return -1
}

// matchingCloseParen returns the offset of the ')' that closes the '(' at open,
// counting only parentheses in code regions so that a ')' inside a message
// string does not close the call. Returns -1 when no match is found within
// maxLogCallScan bytes.
func matchingCloseParen(regions []lexctx.Region, content []byte, open int) int {
	limit := min(open+maxLogCallScan, len(content))
	depth := 0
	for i := open; i < limit; i++ {
		if lexctx.KindAt(regions, i) != lexctx.KindCode {
			continue
		}
		switch content[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// hasCodeWordByte reports whether content[from:to) contains an identifier byte
// that sits in a code region — the evidence that a value, and not just constant
// text, is part of the call.
func hasCodeWordByte(regions []lexctx.Region, content []byte, from, to int) bool {
	for i := from; i < to; i++ {
		if !isWordByte(content[i]) {
			continue
		}
		if lexctx.KindAt(regions, i) == lexctx.KindCode {
			return true
		}
	}
	return false
}

// isWordByte reports whether b can appear in an identifier.
func isWordByte(b byte) bool {
	return b == '_' ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9')
}
