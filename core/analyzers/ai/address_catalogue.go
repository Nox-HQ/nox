package ai

import (
	"bytes"
	"net"
	"strings"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
)

// maxCatalogueScan bounds how far the collection walk looks for the brackets
// around a match, so a stray quote in a large file cannot make it walk the
// whole file per finding.
const maxCatalogueScan = 64 << 10

// catalogueHostnames are the metadata endpoints MCP-018 names by hostname. An
// IP or CIDR entry is recognised by parsing it.
var catalogueHostnames = map[string]bool{
	"metadata.google.internal": true,
	"metadata.azure.com":       true,
}

// keywordsBeforeParen are the words that may sit before a bare `(` without
// making it a call: `for ip in (...)`, `return (...)`.
var keywordsBeforeParen = map[string]bool{
	"in": true, "return": true, "yield": true, "and": true, "or": true, "not": true,
}

// isAddressCatalogue reports whether an MCP-018 match is one entry of a
// literal collection holding nothing but network addresses: two or more
// entries, each a bare string literal that parses as an IP, a CIDR or a
// metadata hostname.
//
// That is how code writes the set of addresses it refuses (#929, pydantic-ai's
// SSRF guard), and a fetch target is never written that way: a target is a URL,
// an assignment, or an argument to the call that reaches it. The collection is
// read from the lexer's regions, so a comment beside an entry is skipped and
// never consulted — a comment cannot switch the rule off.
func isAddressCatalogue(lang lexctx.Lang, content []byte, f *findings.Finding) bool {
	if lang == lexctx.LangUnknown {
		return false
	}
	start := lexctx.LineColToOffset(content, f.Location.StartLine, f.Location.StartColumn)
	end := lexctx.LineColToOffset(content, f.Location.EndLine, f.Location.EndColumn)
	regions := lexctx.Classify(lang, content)
	idx := lexctx.RegionAt(regions, start)
	if idx < 0 || regions[idx].Kind != lexctx.KindString || end <= start {
		return false
	}
	// The literal must be the address alone: no scheme, path or port.
	if !bytes.Equal(lexctx.StringBody(content, regions[idx]), content[start:end]) {
		return false
	}
	open, closer, ok := enclosingBrackets(content, regions, idx)
	if !ok || isCallParen(content, open) {
		return false
	}
	entries, ok := collectionEntries(content, regions, open, closer)
	if !ok || len(entries) < 2 {
		return false
	}
	for _, e := range entries {
		if !isAddressLiteral(e) {
			return false
		}
	}
	return true
}

// enclosingBrackets finds the unmatched opening and closing brackets around
// regions[idx], counting brackets in code only.
func enclosingBrackets(content []byte, regions []lexctx.Region, idx int) (open, closer int, ok bool) {
	open, closer = -1, -1
	depth := 0
	for i := idx - 1; i >= 0 && open < 0 && regions[idx].Start-regions[i].End < maxCatalogueScan; i-- {
		if regions[i].Kind != lexctx.KindCode {
			continue
		}
		for p := regions[i].End - 1; p >= regions[i].Start; p-- {
			if d := bracketDelta(content[p]); d < 0 {
				depth++
			} else if d > 0 {
				if depth == 0 {
					open = p
					break
				}
				depth--
			}
		}
	}
	depth = 0
	for i := idx + 1; i < len(regions) && closer < 0 && regions[i].Start-regions[idx].End < maxCatalogueScan; i++ {
		if regions[i].Kind != lexctx.KindCode {
			continue
		}
		for p := regions[i].Start; p < regions[i].End; p++ {
			if d := bracketDelta(content[p]); d > 0 {
				depth++
			} else if d < 0 {
				if depth == 0 {
					closer = p
					break
				}
				depth--
			}
		}
	}
	if open < 0 || closer < 0 {
		return 0, 0, false
	}
	return open, closer, matchingBracket(content[open]) == content[closer]
}

// bracketDelta is +1 for an opening bracket, -1 for a closing one, 0 otherwise.
func bracketDelta(c byte) int {
	switch c {
	case '(', '[', '{':
		return 1
	case ')', ']', '}':
		return -1
	}
	return 0
}

func matchingBracket(c byte) byte {
	switch c {
	case '(':
		return ')'
	case '[':
		return ']'
	}
	return '}'
}

// isCallParen reports whether the `(` at open begins an argument list: a
// name, or a call or index result, directly before it. A metadata address
// passed to a call is the target this rule exists for.
func isCallParen(content []byte, open int) bool {
	if content[open] != '(' {
		return false
	}
	p := open - 1
	for p >= 0 && (content[p] == ' ' || content[p] == '\t') {
		p--
	}
	if p < 0 {
		return false
	}
	if content[p] == ')' || content[p] == ']' {
		return true
	}
	wordEnd := p + 1
	for p >= 0 && isIdentByte(content[p]) {
		p--
	}
	word := string(content[p+1 : wordEnd])
	return word != "" && !keywordsBeforeParen[word]
}

func isIdentByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// collectionEntries returns the string bodies of the entries between open and
// closer. Each entry must be one string literal, or one string literal keyed
// to a set member's value (`"addr": true`, Go's `map[string]bool` idiom). It
// fails on anything else: a name, a call, a key mapped to a value, a nested
// collection or an interpolation.
func collectionEntries(content []byte, regions []lexctx.Region, open, closer int) ([]string, bool) {
	var entries []string
	var current []byte
	var before, after []byte // code around the literal, whitespace removed
	literals := 0
	flush := func() bool {
		switch {
		case literals > 1 || len(before) > 0:
			return false
		case literals == 1 && !setMemberValue[string(after)]:
			return false
		case literals == 0 && len(after) > 0:
			return false
		case literals == 1:
			entries = append(entries, string(current))
		}
		current, before, after, literals = nil, nil, nil, 0
		return true
	}
	for i := lexctx.RegionAt(regions, open+1); i >= 0 && i < len(regions) && regions[i].Start < closer; i++ {
		r := regions[i]
		switch r.Kind {
		case lexctx.KindComment:
			continue
		case lexctx.KindString:
			literals++
			current = lexctx.StringBody(content, r)
			continue
		}
		for p := max(r.Start, open+1); p < min(r.End, closer); p++ {
			switch c := content[p]; {
			case c == ',':
				if !flush() {
					return nil, false
				}
			case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			case literals == 0:
				before = append(before, c)
			default:
				after = append(after, c)
			}
		}
	}
	if !flush() {
		return nil, false
	}
	return entries, true
}

// setMemberValue lists what may follow an entry's literal, whitespace removed:
// nothing, or the value a map-as-set gives every member.
var setMemberValue = map[string]bool{
	"": true, ":true": true, ":True": true, ":struct{}{}": true, ":{}": true,
}

// isAddressLiteral reports whether s is an IP, a CIDR or a metadata hostname.
func isAddressLiteral(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	return catalogueHostnames[strings.ToLower(s)]
}
