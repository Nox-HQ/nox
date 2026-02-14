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
const defaultEntropyThreshold = 5.0

// contextBoostReduction is subtracted from the entropy threshold when the
// line containing a candidate includes a secret-suggestive variable name.
const contextBoostReduction = 0.5

// minCandidateLen is the minimum length for any candidate string. Strings
// shorter than this are ignored to avoid false positives on short tokens.
const minCandidateLen = 12

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

// base64Re matches base64-encoded sequences of at least 30 characters.
var base64Re = regexp.MustCompile(`[A-Za-z0-9+/=]{30,}`)

// hexRe matches hexadecimal sequences of at least 32 characters.
var hexRe = regexp.MustCompile(`[0-9a-fA-F]{32,}`)

// EntropyMatcher implements the Matcher interface using Shannon entropy
// analysis. It extracts candidate strings from file content using multiple
// tokenizers (quoted strings, assignment RHS values, base64 blobs, hex
// strings) and flags candidates whose entropy exceeds a configurable
// threshold.
type EntropyMatcher struct{}

// Match scans content line by line, extracts candidate strings using
// multiple tokenizers, calculates Shannon entropy for each candidate, and
// returns matches that exceed the threshold. The threshold can be
// customised via rule.Metadata["entropy_threshold"]. When
// rule.Metadata["require_context"] is "true", candidates are only
// reported if the line also contains a secret-suggestive keyword.
func (m *EntropyMatcher) Match(content []byte, rule *Rule) []MatchResult {
	threshold := defaultEntropyThreshold
	if v, ok := rule.Metadata["entropy_threshold"]; ok {
		if parsed, err := strconv.ParseFloat(v, 64); err == nil {
			threshold = parsed
		}
	}

	requireContext := rule.Metadata["require_context"] == "true"

	lines := bytes.Split(content, []byte("\n"))
	var results []MatchResult

	for lineIdx, line := range lines {
		lineStr := string(line)
		lineLower := strings.ToLower(lineStr)

		// Determine whether this line has secret-suggestive context.
		boost := hasSecretContext(lineLower)

		// When require_context is set, skip lines without secret context
		// entirely. This prevents low-confidence rules from firing on
		// lines that contain no secret-suggestive keywords.
		if requireContext && !boost {
			continue
		}

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

		// Tokenizer 1: quoted strings (single and double quoted, >= minCandidateLen chars).
		extractQuoted(lineStr, addCandidate)

		// Tokenizer 2: assignment RHS values.
		extractAssignmentRHS(lineStr, addCandidate)

		// Tokenizer 3: base64 blobs (30+ chars).
		extractRegexCandidates(lineStr, base64Re, 30, addCandidate)

		// Tokenizer 4: hex strings (32+ chars).
		extractRegexCandidates(lineStr, hexRe, 32, addCandidate)

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
	if s == "" {
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
// git SHAs, Go import paths, file paths, camelCase identifiers, version
// strings, and other patterns that would cause false positives.
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

	// File paths and Go import paths (contains / or \ but not base64
	// special chars like + or =).
	if strings.ContainsAny(s, "/\\") && !strings.ContainsAny(s, "+=") {
		return true
	}

	// Git commit SHAs: exactly 40 hex characters.
	if len(s) == 40 && isAllHex(s) {
		return true
	}

	// Abbreviated git SHAs pinned in GitHub Actions: exactly 40 hex chars
	// is handled above; also skip longer hex-only strings that look like
	// checksums (e.g. SHA-256 = 64 hex chars, SHA-512 = 128 hex chars).
	if (len(s) == 64 || len(s) == 128) && isAllHex(s) {
		return true
	}

	// Version strings (e.g., "v1.2.3", "1.0.0-beta.1").
	if isVersionString(s) {
		return true
	}

	// camelCase or PascalCase identifiers: letters and digits only, with
	// at least one uppercase letter following a lowercase letter.
	if isCamelOrPascalCase(s) {
		return true
	}

	// Strings that are mostly digits (>70%) — likely numeric IDs, not secrets.
	if isMostlyDigits(s) {
		return true
	}

	// All uppercase letters only (likely a constant name like PRODUCTION).
	if isAllUpperAlpha(s) {
		return true
	}

	return false
}

// isAllHex returns true if every character in s is a hexadecimal digit.
func isAllHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return s != ""
}

// isVersionString returns true if s looks like a semver or version string.
func isVersionString(s string) bool {
	if s == "" {
		return false
	}
	start := s
	if s[0] == 'v' || s[0] == 'V' {
		start = s[1:]
	}
	if start == "" {
		return false
	}
	// Must start with a digit and contain at least one dot.
	if start[0] < '0' || start[0] > '9' {
		return false
	}
	return strings.Contains(start, ".")
}

// isCamelOrPascalCase returns true if s is a camelCase or PascalCase
// identifier: only letters and digits, with at least one transition from
// lowercase to uppercase, and at most 20% digits (to distinguish real
// identifiers from random-looking secret tokens).
func isCamelOrPascalCase(s string) bool {
	if len(s) < 4 {
		return false
	}
	hasTransition := false
	prevLower := false
	letters := 0
	digits := 0
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false // non-alphanumeric chars disqualify
		}
		if unicode.IsDigit(r) {
			digits++
		} else {
			letters++
		}
		if prevLower && unicode.IsUpper(r) {
			hasTransition = true
		}
		prevLower = unicode.IsLower(r)
	}
	if !hasTransition {
		return false
	}
	// Real identifiers are mostly letters. Random tokens have lots of digits.
	total := letters + digits
	if total == 0 {
		return false
	}
	return float64(digits)/float64(total) <= 0.2
}

// isMostlyDigits returns true if more than 70% of the characters in s are
// digits.
func isMostlyDigits(s string) bool {
	if s == "" {
		return false
	}
	digits := 0
	total := 0
	for _, r := range s {
		total++
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	return float64(digits)/float64(total) > 0.7
}

// isAllUpperAlpha returns true if every character in s is an uppercase ASCII
// letter.
func isAllUpperAlpha(s string) bool {
	if len(s) < 4 {
		return false
	}
	for _, r := range s {
		if !unicode.IsUpper(r) || !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}
