package rules

import (
	"bytes"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// defaultEntropyThreshold is the minimum Shannon entropy for a candidate
// string to be flagged as a potential secret. This value is used when the
// rule does not specify an "entropy_threshold" metadata key.
const defaultEntropyThreshold = 4.5

// contextBoostReduction is subtracted from the entropy threshold when the
// line containing a candidate includes a secret-suggestive variable name.
const contextBoostReduction = 0.5

// minCandidateLen is the minimum length for any candidate string. Strings
// shorter than this are ignored to avoid false positives on short tokens.
const minCandidateLen = 8

// secretHints are lowercase substrings that, when present in the same line
// as a candidate, lower the entropy threshold to increase detection
// sensitivity.
var secretHints = []string{
	"password",
	"secret",
	"key",
	"token",
	"credential",
	"api_key",
	"private",
}

// base64Re matches base64-encoded sequences of at least 20 characters.
var base64Re = regexp.MustCompile(`[A-Za-z0-9+/=]{20,}`)

// hexRe matches hexadecimal sequences of at least 16 characters.
var hexRe = regexp.MustCompile(`[0-9a-fA-F]{16,}`)

// EntropyMatcher implements the Matcher interface using Shannon entropy
// analysis. It extracts candidate strings from file content using multiple
// tokenizers (quoted strings, assignment RHS values, base64 blobs, hex
// strings) and flags candidates whose entropy exceeds a configurable
// threshold.
type EntropyMatcher struct{}

// Match scans content line by line, extracts candidate strings using
// multiple tokenizers, calculates Shannon entropy for each candidate, and
// returns matches that exceed the threshold. The threshold can be
// customised via rule.Metadata["entropy_threshold"].
func (m *EntropyMatcher) Match(content []byte, rule Rule) []MatchResult {
	threshold := defaultEntropyThreshold
	if v, ok := rule.Metadata["entropy_threshold"]; ok {
		if parsed, err := strconv.ParseFloat(v, 64); err == nil {
			threshold = parsed
		}
	}

	lines := bytes.Split(content, []byte("\n"))
	var results []MatchResult

	for lineIdx, line := range lines {
		lineStr := string(line)
		lineLower := strings.ToLower(lineStr)

		// Determine whether this line has secret-suggestive context.
		boost := hasSecretContext(lineLower)

		effective := threshold
		if boost {
			effective -= contextBoostReduction
		}

		// Collect unique candidates from all tokenizers, tracking their
		// column positions. Use a map keyed by "col:text" to deduplicate
		// overlapping extractions.
		type candidate struct {
			col  int
			text string
		}
		seen := make(map[string]struct{})
		var candidates []candidate

		addCandidate := func(col int, text string) {
			key := strconv.Itoa(col) + ":" + text
			if _, dup := seen[key]; dup {
				return
			}
			seen[key] = struct{}{}
			candidates = append(candidates, candidate{col: col, text: text})
		}

		// Tokenizer 1: quoted strings (single and double quoted, >= 8 chars).
		extractQuoted(lineStr, addCandidate)

		// Tokenizer 2: assignment RHS values.
		extractAssignmentRHS(lineStr, addCandidate)

		// Tokenizer 3: base64 blobs.
		extractRegexCandidates(lineStr, base64Re, 20, addCandidate)

		// Tokenizer 4: hex strings.
		extractRegexCandidates(lineStr, hexRe, 16, addCandidate)

		for _, c := range candidates {
			if len(c.text) < minCandidateLen {
				continue
			}
			if isLikelyNotSecret(c.text) {
				continue
			}
			entropy := ShannonEntropy(c.text)
			if entropy >= effective {
				results = append(results, MatchResult{
					Line:      lineIdx + 1, // 1-based
					Column:    c.col,
					MatchText: c.text,
				})
			}
		}
	}

	return results
}

// ShannonEntropy calculates the Shannon entropy of a string in bits per
// character. Higher values indicate more randomness. Exported for testing.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	length := float64(len([]rune(s)))
	var entropy float64
	for _, count := range freq {
		p := count / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// hasSecretContext returns true if the line contains any secret-suggestive
// variable names. The line must already be lowercased.
func hasSecretContext(lineLower string) bool {
	for _, hint := range secretHints {
		if strings.Contains(lineLower, hint) {
			return true
		}
	}
	return false
}

// extractQuoted finds single- and double-quoted strings in line that are
// at least minCandidateLen characters long (excluding quotes). It calls
// addFn with the 1-based column of the quoted value and the value itself.
func extractQuoted(line string, addFn func(col int, text string)) {
	for _, quote := range []byte{'"', '\''} {
		i := 0
		for i < len(line) {
			start := strings.IndexByte(line[i:], quote)
			if start == -1 {
				break
			}
			start += i // absolute position of opening quote
			end := strings.IndexByte(line[start+1:], quote)
			if end == -1 {
				break
			}
			end += start + 1 // absolute position of closing quote
			value := line[start+1 : end]
			if len(value) >= minCandidateLen {
				addFn(start+2, value) // 1-based column of value start
			}
			i = end + 1
		}
	}
}

// extractAssignmentRHS finds values after =, :, or => operators. A
// candidate RHS is an alphanumeric+special-char token of at least 16
// characters.
func extractAssignmentRHS(line string, addFn func(col int, text string)) {
	// Find assignment operators and extract the RHS.
	for i := 0; i < len(line); i++ {
		// Detect =>, =, or : (but not ::)
		var rhsStart int
		switch {
		case i+1 < len(line) && line[i] == '=' && line[i+1] == '>':
			rhsStart = i + 2
		case line[i] == '=' && (i == 0 || line[i-1] != '!' && line[i-1] != '<' && line[i-1] != '>'):
			// Skip == comparisons.
			if i+1 < len(line) && line[i+1] == '=' {
				i++
				continue
			}
			rhsStart = i + 1
		case line[i] == ':' && (i+1 >= len(line) || line[i+1] != ':'):
			rhsStart = i + 1
		default:
			continue
		}

		// Skip whitespace after the operator.
		for rhsStart < len(line) && (line[rhsStart] == ' ' || line[rhsStart] == '\t') {
			rhsStart++
		}

		// Skip any opening quote on the RHS — quoted values are handled by
		// extractQuoted. We only want unquoted tokens here.
		if rhsStart < len(line) && (line[rhsStart] == '"' || line[rhsStart] == '\'') {
			i = rhsStart
			continue
		}

		// Extract a contiguous token of alphanumeric + special chars.
		rhsEnd := rhsStart
		for rhsEnd < len(line) && isTokenChar(line[rhsEnd]) {
			rhsEnd++
		}

		token := line[rhsStart:rhsEnd]
		if len(token) >= 16 {
			addFn(rhsStart+1, token) // 1-based column
		}

		i = rhsEnd
	}
}

// isTokenChar returns true for characters that commonly appear in secret
// tokens: alphanumeric, +, /, =, -, _, .
func isTokenChar(c byte) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '+' || c == '/' || c == '=' ||
		c == '-' || c == '_' || c == '.'
}

// extractRegexCandidates finds all matches of re in line with at least
// minLen characters and passes them to addFn.
func extractRegexCandidates(line string, re *regexp.Regexp, minLen int, addFn func(col int, text string)) {
	locs := re.FindAllStringIndex(line, -1)
	for _, loc := range locs {
		text := line[loc[0]:loc[1]]
		if len(text) >= minLen {
			addFn(loc[0]+1, text) // 1-based column
		}
	}
}

// isLikelyNotSecret returns true for strings that look like common
// non-secret values: URLs, all-lowercase dictionary-like words, UUIDs,
// and other patterns that would cause false positives.
func isLikelyNotSecret(s string) bool {
	// URLs starting with http:// or https://.
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return true
	}

	// All lowercase letters (likely a dictionary word or path).
	allLower := true
	for _, r := range s {
		if !unicode.IsLetter(r) {
			allLower = false
			break
		}
		if !unicode.IsLower(r) {
			allLower = false
			break
		}
	}
	if allLower {
		return true
	}

	return false
}
