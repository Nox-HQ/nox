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

// candidateKind records which tokenizer produced a candidate. It is the
// tokenizer, not the text, that decides: hex is a subset of the base64
// alphabet, so re-testing a matched string cannot tell the two apart.
//
// A candidate carries the SET of kinds that found it, not one kind, because the
// tokenizers genuinely overlap — `secret_key = xK9mR3pZ...` is both an
// assignment RHS and a base64-shaped blob, and both descriptions are true. A
// single kind would mean whichever tokenizer ran first stole the candidate from
// the others, silently disabling the rules scoped to them.
type candidateKind string

// The kinds, one per tokenizer.
const (
	candidateQuoted     candidateKind = "quoted"
	candidateAssignment candidateKind = "assignment"
	candidateBase64     candidateKind = "base64"
	candidateHex        candidateKind = "hex"
)

// candidateMatchesKinds reports whether a candidate found by the kinds in got is
// one that a rule scoped to want should report. A rule that declares no kinds
// (want == nil) takes everything, as every entropy rule did before kinds
// existed.
func candidateMatchesKinds(got, want map[candidateKind]bool) bool {
	if want == nil {
		return true
	}
	for k := range want {
		if got[k] {
			return true
		}
	}
	return false
}

// parseCandidateKinds reads a rule's "candidate_kinds" metadata: a
// comma-separated list of the kinds that rule reports on. An empty or absent
// value means every kind, which is what every rule did before kinds existed and
// what rules that have not opted in still do.
//
// Scoping exists because SEC-161/162/163 share one matcher. Without it the rule
// ID on a finding names the rule rather than the candidate, so the rule called
// "High-entropy hex string" reported an identifier with no hex in it (#467).
func parseCandidateKinds(rule *Rule) map[candidateKind]bool {
	raw := strings.TrimSpace(rule.Metadata["candidate_kinds"])
	if raw == "" {
		return nil
	}
	kinds := map[candidateKind]bool{}
	for _, part := range strings.Split(raw, ",") {
		if k := candidateKind(strings.TrimSpace(part)); k != "" {
			kinds[k] = true
		}
	}
	if len(kinds) == 0 {
		return nil
	}
	return kinds
}

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
	wantKinds := parseCandidateKinds(rule)

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
			col   int
			text  string
			kinds map[candidateKind]bool
		}
		index := make(map[string]int)
		var candidates []candidate

		// collectAs returns an add function that records kind against the
		// (column, text) pair, unioning with any kind already recorded there.
		// Tokenizer order is therefore irrelevant.
		collectAs := func(kind candidateKind) func(int, string) {
			return func(col int, text string) {
				key := strconv.Itoa(col) + ":" + text
				if i, dup := index[key]; dup {
					candidates[i].kinds[kind] = true
					return
				}
				index[key] = len(candidates)
				candidates = append(candidates, candidate{
					col: col, text: text, kinds: map[candidateKind]bool{kind: true},
				})
			}
		}

		// Tokenizer 1: quoted strings (single and double quoted, >= minCandidateLen chars).
		extractQuoted(lineStr, collectAs(candidateQuoted))

		// Tokenizer 2: assignment RHS values.
		extractAssignmentRHS(lineStr, collectAs(candidateAssignment))

		// Tokenizer 3: base64 blobs (30+ chars).
		extractRegexCandidates(lineStr, base64Re, 30, collectAs(candidateBase64))

		// Tokenizer 4: hex strings (32+ chars).
		extractRegexCandidates(lineStr, hexRe, 32, collectAs(candidateHex))

		for _, c := range candidates {
			if !candidateMatchesKinds(c.kinds, wantKinds) {
				continue
			}
			if len(c.text) < minCandidateLen {
				continue
			}
			if isLikelyNotSecret(c.text) {
				continue
			}
			// Subresource Integrity (SRI) hashes — a base64 digest prefixed by
			// its algorithm (sha256-/sha384-/sha512-) in HTML/JSX/struct tags —
			// are public integrity values, not credentials. Skip a candidate
			// whose base64 body is immediately preceded by an SRI prefix.
			if isSRIIntegrityHash(lineStr, c.col) {
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
		// A token immediately followed by '(' is a function or method call, not
		// a value. This matters because ':' is treated as an assignment operator
		// above, which is correct for YAML/JSON (`api_key: abc…`) but also fires
		// on a struct-literal field in Go, Rust or Swift:
		//
		//	Hook: domain.PrePush.ConfigKey(),
		//
		// There the "RHS" is the selector expression `domain.PrePush.ConfigKey`,
		// which has no value at scan time. A literal secret is never followed by
		// an open paren, so skipping calls costs no recall.
		if rhsEnd < len(line) && line[rhsEnd] == '(' {
			i = rhsEnd
			continue
		}
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
	// Natural-language prose, SQL, error-message format strings, and prompt
	// templates contain internal whitespace; a compact secret token — API key,
	// token, hash, base64/hex blob — never does. This is the dominant
	// false-positive source for the generic entropy detectors on prose-heavy
	// codebases: a 120-char English sentence has high aggregate entropy but is
	// not a credential (#104). Real base64/hex secrets are still caught, because
	// the base64/hex tokenizers extract the token itself (no surrounding
	// whitespace) — only the whole-string quoted/assignment candidates carry
	// prose, and a real secret in a quoted string is the compact token anyway.
	if strings.ContainsAny(s, " \t") {
		return true
	}

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

	// SCREAMING_SNAKE_CASE constant names (e.g. DEFAULT_THREAD_ID_KEY).
	if isScreamingSnakeCase(s) {
		return true
	}

	// All-lowercase snake_case or dot-separated attribute access chains
	// (e.g. resolved_options.run_context_thread_id_key). Real secret tokens
	// never follow this pattern.
	if isLowercaseDotChain(s) {
		return true
	}

	// Template expressions — contain '{' and '}' (Python f-strings, shell
	// variable substitutions). Template placeholders are never raw credentials.
	if containsTemplateBraces(s) {
		return true
	}

	return false
}

// sriPrefixes are the algorithm labels that precede the base64 body of a
// Subresource Integrity hash, e.g. sha384-<base64>.
var sriPrefixes = []string{"sha256-", "sha384-", "sha512-"}

// isSRIIntegrityHash reports whether the candidate string beginning at the
// given 1-based column in line is the base64 body of a Subresource Integrity
// (SRI) hash — i.e. immediately preceded by an SRI algorithm prefix such as
// "sha384-". Such hashes are public content digests, never secrets, so they
// must not fire the entropy detectors. The prefix must be a whole token: the
// character before it (if any) must not be alphanumeric, so "mysha384-…" (a
// coincidental substring) is not treated as SRI.
func isSRIIntegrityHash(line string, col int) bool {
	// col is 1-based; the candidate starts at byte index col-1.
	start := col - 1
	if start < 0 || start > len(line) {
		return false
	}
	prefixRegion := strings.ToLower(line[:start])
	for _, p := range sriPrefixes {
		if !strings.HasSuffix(prefixRegion, p) {
			continue
		}
		before := len(prefixRegion) - len(p)
		if before == 0 {
			return true
		}
		if b := prefixRegion[before-1]; !isAlphaNum(b) {
			return true
		}
	}
	return false
}

// isAlphaNum reports whether b is an ASCII letter or digit.
func isAlphaNum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
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

// isScreamingSnakeCase returns true if s consists only of uppercase ASCII
// letters, digits, and underscores with at least one underscore. These are
// constant names (e.g. DEFAULT_RUN_CONTEXT_THREAD_ID_KEY) and are never
// credentials.
func isScreamingSnakeCase(s string) bool {
	if len(s) < 4 {
		return false
	}
	hasUnderscore := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '_':
			hasUnderscore = true
		case c >= 'A' && c <= 'Z':
			// ok
		case c >= '0' && c <= '9':
			// ok
		default:
			return false
		}
	}
	return hasUnderscore
}

// isLowercaseDotChain returns true if s consists only of lowercase ASCII
// letters, digits, underscores, and dots with at least one underscore. These
// are snake_case variable names or attribute access chains
// (e.g. resolved_options.run_context_thread_id_key) and are never credentials.
func isLowercaseDotChain(s string) bool {
	if len(s) < 4 {
		return false
	}
	hasUnderscore := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '_':
			hasUnderscore = true
		case c == '.':
			// ok — dot-separated attribute access
		case c >= 'a' && c <= 'z':
			// ok
		case c >= '0' && c <= '9':
			// ok
		default:
			return false
		}
	}
	return hasUnderscore
}

// containsTemplateBraces returns true if s contains both '{' and '}',
// indicating a template expression (Python f-strings, shell variable
// substitution, etc.). Template placeholders are never raw credentials.
func containsTemplateBraces(s string) bool {
	return strings.ContainsRune(s, '{') && strings.ContainsRune(s, '}')
}
