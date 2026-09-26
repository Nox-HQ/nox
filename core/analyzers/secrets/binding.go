package secrets

import (
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
)

// bindingRuleIDs are the vendor rules whose claim is "a value bound to a name
// that starts with the vendor's word" (bcb182c): Namecheap, Wave, FCM, Lob,
// Salesforce, Jenkins, Split, Heap and FullStory. None of those vendors
// publishes a credential format the rule could encode, so the rule accepts a
// run of N letters and digits after `<word>…=` or `<word>…:`.
//
// The word binds loosely on purpose — `split_api_key`, `SPLIT_KEY`, `split.key`
// — and that is also how `splitter`, `heapq`, `waveform` and `lobby` reach it.
var bindingRuleIDs = map[string]bool{
	"SEC-540": true, "SEC-590": true, "SEC-616": true, "SEC-629": true, "SEC-635": true,
	"SEC-652": true, "SEC-659": true, "SEC-664": true, "SEC-665": true,
}

// continuesAsIdentifier reports whether a binding rule's value is really the
// first N characters of a code identifier that goes on into a call, an
// attribute or an index.
//
// `splitter = SemanticDoubleMergingSplitterNodeParser(` reported SEC-659
// "Split API Key" five times in llama_index's tests: `splitter` starts with
// `split`, and the class name's first 32 characters are 32 letters. A
// credential ends — at a quote, whitespace, a separator, the end of the line.
// An identifier continues, and lands on `(`, `.` or `[`.
//
// This is a refiner, not a longer pattern, deliberately: the rules' match text
// is what their findings are fingerprinted on, and a pattern that consumed the
// character after the value would move the fingerprint of every true positive
// already baselined or waived.
func continuesAsIdentifier(content []byte, f *findings.Finding) bool {
	if !bindingRuleIDs[f.RuleID] {
		return false
	}
	i := lexctx.LineColToOffset(content, f.Location.EndLine, f.Location.EndColumn)
	for i < len(content) && isAlnum(content[i]) {
		i++
	}
	if i >= len(content) {
		return false
	}
	switch content[i] {
	case '(', '.', '[':
		return true
	}
	return false
}

func isAlnum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}
