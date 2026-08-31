package rules

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/rules/structural"
)

// MatchResult describes a single match of a rule pattern within file content.
type MatchResult struct {
	Line      int
	Column    int
	MatchText string

	// Structural, when non-empty, is what parsing the document established
	// about this result — "the cloudformation resource \"LogBucket\"
	// (AWS::S3::Bucket) was parsed and sets no BucketEncryption".
	//
	// It is carried on the result rather than recorded where it is computed
	// because the matcher has no reasoning store and must not grow one: the
	// rule engine stays a pure function of content and rules, and the analyzer
	// that owns the evidence seam turns this sentence into a claim.
	//
	// Empty means the result came from text matching, which is a heuristic. The
	// difference is the whole point, so it must never be filled in by the
	// regex path.
	Structural string
}

// StructuralClaimKey is the finding-metadata key carrying MatchResult.Structural.
//
// Exported because the producer (the rule engine) and the consumer (the IaC
// analyzer's evidence seam) are in different packages, and a metadata key
// spelled twice is a key that eventually gets spelled two ways — after which
// the claim is silently never recorded and the ledger looks exactly as it did
// before the structural path existed.
const StructuralClaimKey = "structural_claim"

// Matcher is the interface that all pattern-matching strategies must satisfy.
// Implementations receive raw file content and a pointer to the triggering
// rule, and return zero or more match results.
type Matcher interface {
	Match(content []byte, rule *Rule) []MatchResult
}

// RegexMatcher implements Matcher using compiled regular expressions. It
// caches compiled patterns to avoid redundant compilation across calls.
// regexCache is a mutex-guarded compiled-pattern cache. Both matcher types
// embed it rather than each carrying its own identical mu+map and compile loop.
type regexCache struct {
	mu    sync.Mutex
	cache map[string]*regexp.Regexp
}

// newRegexCache returns an initialised cache.
func newRegexCache() regexCache { return regexCache{cache: map[string]*regexp.Regexp{}} }

// compile returns the compiled form of pattern, caching it. label names the
// pattern kind for the error message.
func (c *regexCache) compile(pattern, label string) (*regexp.Regexp, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if re, ok := c.cache[pattern]; ok {
		return re, nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("compiling %s %q: %w", label, pattern, err)
	}
	c.cache[pattern] = re
	return re, nil
}

// RegexMatcher matches a rule's regex pattern against file content, caching
// compiled patterns.
type RegexMatcher struct {
	regexCache
}

// NewRegexMatcher returns a RegexMatcher with an initialised pattern cache.
func NewRegexMatcher() *RegexMatcher {
	return &RegexMatcher{regexCache: newRegexCache()}
}

// compile returns a compiled regexp for the given pattern, using the cache
// when possible.
func (m *RegexMatcher) compile(pattern string) (*regexp.Regexp, error) {
	return m.regexCache.compile(pattern, "pattern")
}

// Match finds all occurrences of the rule pattern in content and returns
// their positions as MatchResult values with 1-based line and column numbers.
// When rule.Metadata["secret_shape"] == "true", matches are post-filtered to
// require a secret-shaped value: minimum Shannon entropy, restricted charset,
// and rejection of obvious non-secret patterns (camelCase identifiers,
// version strings, file paths, all-lowercase dictionary words). The minimum
// entropy threshold defaults to 3.0 and can be overridden via
// rule.Metadata["min_entropy"].
func (m *RegexMatcher) Match(content []byte, rule *Rule) []MatchResult {
	re, err := m.compile(rule.Pattern)
	if err != nil {
		return nil
	}

	// Reuse the shared offset helpers (computeLineStarts / makeMatchResult) that
	// AbsenceMatcher already uses, rather than inlining a second copy of the
	// line/column arithmetic.
	lineStarts := computeLineStarts(content)
	matches := re.FindAllIndex(content, -1)
	results := make([]MatchResult, 0, len(matches))
	for _, loc := range matches {
		results = append(results, makeMatchResult(content, lineStarts, loc))
	}

	if rule.Metadata["secret_shape"] == "true" {
		results = filterBySecretShape(results, rule)
	}
	if rule.Metadata["publisher_allowlist"] != "" {
		results = filterByPublisherAllowlist(results, rule)
	}
	return results
}

// filterByPublisherAllowlist drops matches whose `<publisher>/<name>@<ref>`
// reference belongs to a trusted publisher. Used by IAC-013 to silence
// findings on first-party GitHub actions (actions/*, github/*) that ship
// immutable releases via tagged refs and are managed by Dependabot.
//
// The allowlist is read from rule.Metadata["publisher_allowlist"] as a
// comma-separated list (e.g. "actions,github"). Comparison is case-
// insensitive and ignores surrounding whitespace.
func filterByPublisherAllowlist(in []MatchResult, rule *Rule) []MatchResult {
	raw := rule.Metadata["publisher_allowlist"]
	if raw == "" {
		return in
	}
	allowed := make(map[string]struct{})
	for p := range strings.SplitSeq(raw, ",") {
		p = strings.TrimSpace(strings.ToLower(p))
		if p != "" {
			allowed[p] = struct{}{}
		}
	}
	out := in[:0]
	for _, r := range in {
		pub := extractPublisher(r.MatchText)
		if pub != "" {
			if _, ok := allowed[strings.ToLower(pub)]; ok {
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

// extractPublisher returns the publisher segment of a `uses: <pub>/<name>@<ref>`
// match text, or "" when the match doesn't follow that shape.
func extractPublisher(text string) string {
	// Strip the `uses:` prefix and surrounding whitespace.
	idx := strings.Index(strings.ToLower(text), "uses:")
	if idx < 0 {
		return ""
	}
	rest := strings.TrimSpace(text[idx+len("uses:"):])
	slash := strings.Index(rest, "/")
	if slash <= 0 {
		return ""
	}
	return rest[:slash]
}

// filterBySecretShape rejects matches whose text doesn't look like a real
// secret. Used by vendor-name secret rules with loose regex patterns
// (e.g. `[a-zA-Z0-9]{20}`) that would otherwise fire on identifier
// substrings, README example text, or other non-secret content.
func filterBySecretShape(in []MatchResult, rule *Rule) []MatchResult {
	minEntropy := 3.0
	if v, ok := rule.Metadata["min_entropy"]; ok {
		if parsed, err := strconv.ParseFloat(v, 64); err == nil {
			minEntropy = parsed
		}
	}
	out := in[:0]
	for _, r := range in {
		if !isSecretShape(r.MatchText, minEntropy) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// isSecretShape returns true if text has the entropy/character profile of a
// real secret rather than a code identifier or human-readable string.
func isSecretShape(text string, minEntropy float64) bool {
	if len(text) < 12 {
		return false
	}
	if isLikelyNotSecret(text) {
		return false
	}
	if ShannonEntropy(text) < minEntropy {
		return false
	}
	return true
}

// findLine returns the 0-based line index for the given byte offset using a
// linear scan over the precomputed line start offsets.
func findLine(lineStarts []int, offset int) int {
	// Binary search, not a scan. lineStarts is built in ascending order by
	// computeLineStarts, and this is called once per match.
	//
	// The linear version walked the table BACKWARDS from the end, so a match
	// near the top of a file examined almost every entry — worst case for the
	// commonest case. Total cost grew as matches x lines, which made scanning a
	// large, match-dense file (a vendored bundle, a generated client) quadratic.
	// It surfaced as the fuzzer stalling with "context deadline exceeded", a
	// message that reads like flaky infrastructure and was really the engine.
	//
	// Want: the largest i with lineStarts[i] <= offset. SearchInts returns the
	// first index whose value is > offset, so that index minus one is it;
	// clamped at 0 so a negative offset still reports the first line, matching
	// the behaviour this replaced.
	i := sort.SearchInts(lineStarts, offset+1) - 1
	if i < 0 {
		return 0
	}
	return i
}

// AbsenceMatcher implements block-scoped "hardening property absent" detection
// for IaC rules. See the Rule.Absence* fields for the model. It is the RE2-safe
// replacement for the negative-lookahead patterns (?!...) that Go's regexp
// rejected: rather than expressing "resource present but property absent" as a
// single impossible pattern, it locates each anchor, bounds the anchor's real
// structural span, and reports the span when the hardening property is missing.
//
// It is deterministic: for identical content it always yields the same match
// set, computed purely from byte offsets and the rule's patterns.
type AbsenceMatcher struct {
	regexCache
}

// NewAbsenceMatcher returns an AbsenceMatcher with an initialised pattern cache.
func NewAbsenceMatcher() *AbsenceMatcher {
	return &AbsenceMatcher{regexCache: newRegexCache()}
}

// compile returns a compiled regexp for pattern, cached. An empty pattern
// returns (nil, nil) so callers can treat "unset" distinctly from "invalid".
func (m *AbsenceMatcher) compile(pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, nil
	}
	return m.regexCache.compile(pattern, "absence pattern")
}

// stripLineComments removes `#` line comments so a keyword that appears only in
// a comment cannot satisfy an absence rule's required property. A comment can
// never fulfil a "the config must contain X" requirement, so dropping comments
// before the property check is semantically correct.
//
// The decision of where a comment begins is delegated to lexctx — the single
// source of truth for lexical context in Nox — via lexctx.HashCommentStart, so
// no analyzer reinvents "is this `#` a live comment or part of a quoted value".
// That classifier is deliberately conservative in the safe direction: a `#`
// inside a quoted YAML value, a JSON string, or a URL fragment is never treated
// as a comment. This matters because for an absence rule wrongly cutting real
// content turns a present property into an absent one — a false positive, the
// worse failure for a security scanner.
//
// The result is only used for the boolean property check; finding locations
// come from the anchor match against the original content, so the stripped copy
// need not preserve offsets.
func stripLineComments(content []byte) []byte {
	var out []byte
	for lineStart := 0; lineStart <= len(content); {
		nl := bytes.IndexByte(content[lineStart:], '\n')
		var line []byte
		if nl < 0 {
			line = content[lineStart:]
		} else {
			line = content[lineStart : lineStart+nl]
		}

		if cut := lexctx.HashCommentStart(line); cut >= 0 {
			line = bytes.TrimRight(line[:cut], " \t")
		}
		out = append(out, line...)

		if nl < 0 {
			break
		}
		out = append(out, '\n')
		lineStart += nl + 1
	}
	return out
}

// Match reports each AbsenceAnchor occurrence whose span lacks AbsenceProperty
// (and, when set, contains AbsenceRequire). The returned MatchResult points at
// the anchor so the finding lands on the resource declaration.
func (m *AbsenceMatcher) Match(content []byte, rule *Rule) []MatchResult {
	// A rule carrying a structural descriptor asks the document instead of the
	// text. The verdict is authoritative only when it was DECIDED — the content
	// parsed and its schema was recognised — because "I could not read this" is
	// not "there is nothing here", and a scanner that conflates the two turns
	// every unreadable file into an all-clear. Everything else falls through to
	// the patterns below, which is exactly today's behaviour.
	if v, ok := structuralAbsence(content, rule); ok {
		return v
	}

	anchorRe, err := m.compile(rule.AbsenceAnchor)
	if err != nil || anchorRe == nil {
		return nil
	}
	propRe, err := m.compile(rule.AbsenceProperty)
	if err != nil || propRe == nil {
		return nil
	}
	requireRe, err := m.compile(rule.AbsenceRequire)
	if err != nil {
		return nil
	}

	anchors := anchorRe.FindAllIndex(content, -1)
	if len(anchors) == 0 {
		return nil
	}
	lineStarts := computeLineStarts(content)

	// File span is global: the property (and any requirement) is evaluated once
	// over the whole file, and a single deterministic finding is reported at the
	// first anchor. Used for cross-object rules — e.g. a Deployment whose
	// companion PodDisruptionBudget is a separate manifest, or a Dockerfile
	// missing a HEALTHCHECK entirely.
	if rule.AbsenceSpan == "file" || rule.AbsenceSpan == "" {
		// The property is matched against comment-stripped content: a keyword
		// mentioned only in a comment cannot fulfil a "must be present"
		// requirement. The anchor, the requirement and the finding location
		// stay on the original content.
		if propRe.Match(stripLineComments(content)) {
			return nil
		}
		if requireRe != nil && !requireRe.Match(content) {
			return nil
		}
		return []MatchResult{makeMatchResult(content, lineStarts, anchors[0])}
	}

	var results []MatchResult
	seenLine := make(map[int]bool)
	for _, loc := range anchors {
		span := absenceSpan(content, loc, rule.AbsenceSpan)
		if span == nil {
			continue
		}
		if requireRe != nil && !requireRe.Match(span) {
			continue
		}
		if propRe.Match(stripLineComments(span)) {
			continue
		}
		r := makeMatchResult(content, lineStarts, loc)
		// Multiple anchors that resolve to the same line (rare) collapse to one
		// finding, keeping output stable and free of duplicates.
		if seenLine[r.Line] {
			continue
		}
		seenLine[r.Line] = true
		results = append(results, r)
	}
	return results
}

// structuralAbsence evaluates a rule's structural descriptor, returning the
// results and whether the verdict decided the question.
//
// ok=false means fall back to text matching. It covers three distinct cases
// that must all degrade the same way: the rule has no descriptor, the content
// did not parse, or it parsed into a schema this build does not understand.
func structuralAbsence(content []byte, rule *Rule) ([]MatchResult, bool) {
	if len(rule.AbsenceResourceTypes) == 0 || len(rule.AbsencePropertyPath) == 0 {
		return nil, false
	}
	v := structural.Evaluate(content, rule.AbsenceResourceTypes,
		rule.AbsencePropertyPath, rule.AbsenceRequireAll)
	if !v.Decided {
		return nil, false
	}

	// A decided verdict with no absent resources is a real result: the template
	// was read and every resource of this type is configured. Returning an
	// empty slice with ok=true is what stops the regex path from re-reporting
	// what parsing just refuted.
	results := make([]MatchResult, 0, len(v.Absent))
	for _, hit := range v.Absent {
		results = append(results, MatchResult{
			Line:       hit.Line,
			Column:     1,
			MatchText:  hit.Type,
			Structural: hit.Statement(true),
		})
	}
	return results, true
}

// absenceSpan returns the byte slice of content that constitutes the anchor's
// structural span for the given mode, or nil when no complete span exists.
func absenceSpan(content []byte, loc []int, mode string) []byte {
	switch mode {
	case "line":
		return lineSpan(content, loc[0])
	case "line-continued":
		return lineContinuedSpan(content, loc[0])
	case "brace-block":
		return braceBlockFollowing(content, loc[1])
	case "brace-enclosing":
		// JSON bounds a resource by its enclosing { }. A CloudFormation
		// template written in YAML has no braces, so braceBlockEnclosing returns
		// nil and every brace-enclosing absence rule silently fails to fire —
		// measured: IAC-051 flags an unencrypted S3 bucket in a JSON template
		// and misses the identical bucket in YAML, an entire format left
		// unscanned by the CloudFormation absence rules. Fall back to the
		// indentation-bounded span, which is the YAML equivalent of "the block
		// this anchor introduces". The rules already list *.yaml and *.yml in
		// their file patterns, so YAML was always in scope; only the span could
		// not reach it.
		if span := braceBlockEnclosing(content, loc[0]); span != nil {
			return span
		}
		return yamlEnclosingSpan(content, loc[0])
	case "yaml-block":
		return yamlBlockSpan(content, loc[0])
	case "yaml-doc":
		return yamlDocSpan(content, loc[0])
	default:
		return nil
	}
}

// computeLineStarts returns the byte offset at which each line begins.
func computeLineStarts(content []byte) []int {
	lines := bytes.SplitAfter(content, []byte("\n"))
	lineStarts := make([]int, len(lines))
	offset := 0
	for i, line := range lines {
		lineStarts[i] = offset
		offset += len(line)
	}
	return lineStarts
}

// makeMatchResult builds a MatchResult for the match at loc, resolving its
// 1-based line and column from precomputed line starts.
func makeMatchResult(content []byte, lineStarts, loc []int) MatchResult {
	line := findLine(lineStarts, loc[0])
	return MatchResult{
		Line:      line + 1,
		Column:    loc[0] - lineStarts[line] + 1,
		MatchText: string(content[loc[0]:loc[1]]),
	}
}

// lineSpan returns the single line (excluding the trailing newline) that
// contains offset.
func lineSpan(content []byte, offset int) []byte {
	start := offset
	for start > 0 && content[start-1] != '\n' {
		start--
	}
	end := offset
	for end < len(content) && content[end] != '\n' {
		end++
	}
	return content[start:end]
}

// lineContinuedSpan returns the logical line at offset, extended across shell
// line-continuations (a trailing backslash). A Dockerfile RUN whose flags wrap
// onto following lines is thereby treated as one command, so a hardening flag on
// a continuation line is not missed — the precise "property outside the window"
// false positive a single-line span would produce.
func lineContinuedSpan(content []byte, offset int) []byte {
	start := offset
	for start > 0 && content[start-1] != '\n' {
		start--
	}
	end := start
	for end < len(content) {
		lineEnd := end
		for lineEnd < len(content) && content[lineEnd] != '\n' {
			lineEnd++
		}
		trimmed := bytes.TrimRight(content[end:lineEnd], " \t\r")
		cont := len(trimmed) > 0 && trimmed[len(trimmed)-1] == '\\'
		if lineEnd < len(content) {
			end = lineEnd + 1
		} else {
			end = lineEnd
			cont = false
		}
		if !cont {
			break
		}
	}
	return content[start:end]
}

// matchBrace returns the index of the '}' that closes the '{' at openIdx, or -1
// if the block is unterminated. Braces are balanced across nesting; braces
// inside strings are not special-cased, which is adequate for the well-formed
// IaC configs these rules target.
func matchBrace(content []byte, openIdx int) int {
	depth := 0
	for i := openIdx; i < len(content); i++ {
		switch content[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// braceBlockFollowing returns the first balanced {...} block beginning at or
// after `from`, inclusive of both braces. Used for HCL/Terraform where a
// resource header (`resource "aws_s3_bucket" "b"`) precedes its block.
func braceBlockFollowing(content []byte, from int) []byte {
	open := -1
	for i := from; i < len(content); i++ {
		if content[i] == '{' {
			open = i
			break
		}
	}
	if open < 0 {
		return nil
	}
	closeIdx := matchBrace(content, open)
	if closeIdx < 0 {
		return nil
	}
	return content[open : closeIdx+1]
}

// braceBlockEnclosing returns the innermost balanced {...} block whose braces
// surround pos, inclusive. Used for CloudFormation / ARM JSON where the
// resource's Type value sits inside the resource object.
func braceBlockEnclosing(content []byte, pos int) []byte {
	depth := 0
	open := -1
	for i := pos - 1; i >= 0; i-- {
		switch content[i] {
		case '}':
			depth++
		case '{':
			if depth == 0 {
				open = i
			} else {
				depth--
			}
		}
		if open >= 0 {
			break
		}
	}
	if open < 0 {
		return nil
	}
	closeIdx := matchBrace(content, open)
	if closeIdx < 0 {
		return nil
	}
	return content[open : closeIdx+1]
}

// lineIndent returns the number of leading space/tab columns on the line that
// begins at lineStart.
func lineIndent(content []byte, lineStart int) int {
	n := 0
	for i := lineStart; i < len(content) && (content[i] == ' ' || content[i] == '\t'); i++ {
		n++
	}
	return n
}

// yamlBlockSpan returns the anchor's YAML block: the line containing pos plus
// every following line indented deeper than it (blank lines are absorbed rather
// than ending the block). This is the structural extent of the key the anchor
// sits on — e.g. a `securityContext:` mapping and all of its children.
func yamlBlockSpan(content []byte, pos int) []byte {
	start := pos
	for start > 0 && content[start-1] != '\n' {
		start--
	}
	baseIndent := lineIndent(content, start)

	// Whether the anchor line itself opens a sequence entry ("- ..."). This
	// distinguishes the two same-indent cases below: a mapping-key anchor
	// ("containers:") owns its equally-indented "-" children, but a sequence-entry
	// anchor ("- name: app") is a sibling of the next equally-indented "-" and
	// must stop before it.
	anchorLineEnd := start
	for anchorLineEnd < len(content) && content[anchorLineEnd] != '\n' {
		anchorLineEnd++
	}
	anchorTrimmed := bytes.TrimSpace(content[start:anchorLineEnd])
	anchorIsSeqItem := len(anchorTrimmed) > 0 && anchorTrimmed[0] == '-'

	end := start
	first := true
	for end < len(content) {
		lineEnd := end
		for lineEnd < len(content) && content[lineEnd] != '\n' {
			lineEnd++
		}
		if !first {
			trimmed := bytes.TrimSpace(content[end:lineEnd])
			if len(trimmed) > 0 {
				ind := lineIndent(content, end)
				// A block sequence may be indented the SAME as its parent key
				// (YAML allows `containers:` and its `- name:` items at equal
				// indentation), so when the anchor is a mapping key a same-indent
				// sequence entry ("-") still belongs to the block. But when the
				// anchor is itself a sequence entry, the next same-indent "-" is a
				// SIBLING list item, not a child, and must terminate the block —
				// otherwise the anchor item would absorb its siblings' properties
				// (a false negative). The block therefore ends at the first line
				// that is shallower, or at the same indent when the line is a
				// sibling: a mapping key, or a sequence entry when the anchor was
				// one too.
				isSeqItem := trimmed[0] == '-'
				sameIndentSibling := !isSeqItem || anchorIsSeqItem
				if ind < baseIndent || (ind == baseIndent && sameIndentSibling) {
					break
				}
			}
		}
		first = false
		if lineEnd < len(content) {
			end = lineEnd + 1
		} else {
			end = lineEnd
			break
		}
	}
	return content[start:end]
}

// yamlDocSpan returns the `---`/`...`-delimited YAML document (or the whole file
// when there are no separators) that contains pos. Used for K8s resources whose
// companion property may sit anywhere within the same document — e.g. a
// Deployment and a `securityContext:` nested several levels below its `kind:`.
// yamlEnclosingSpan returns the YAML mapping block that ENCLOSES the anchor,
// which is the indentation analogue of braceBlockEnclosing.
//
// The distinction from yamlBlockSpan is the whole point, and it was found by a
// false positive. yamlBlockSpan bounds the block an anchor INTRODUCES — for an
// anchor on a `Type: AWS::S3::Bucket` line, that is just the scalar, and a
// sibling `BucketEncryption:` falls outside it, so an encrypted bucket looked
// unencrypted. brace-enclosing walks OUT to the object containing the anchor;
// this is its YAML equivalent: from the anchor, up to the nearest less-indented
// line (the resource key), then that key's whole block.
func yamlEnclosingSpan(content []byte, pos int) []byte {
	// The anchor's own line start and indent.
	lineStart := pos
	for lineStart > 0 && content[lineStart-1] != '\n' {
		lineStart--
	}
	anchorIndent := lineIndent(content, lineStart)

	// Walk up to the nearest preceding non-blank line with a smaller indent:
	// the mapping key that owns the block the anchor sits in.
	parentStart := lineStart
	for parentStart > 0 {
		// Move to the previous line.
		prevEnd := parentStart - 1
		ps := prevEnd
		for ps > 0 && content[ps-1] != '\n' {
			ps--
		}
		if trimmed := bytes.TrimSpace(content[ps:prevEnd]); len(trimmed) > 0 {
			if lineIndent(content, ps) < anchorIndent {
				parentStart = ps
				break
			}
		}
		parentStart = ps
		if ps == 0 {
			break
		}
	}
	// yamlBlockSpan from the parent key captures the parent and all of its more-
	// indented children — the enclosing resource block.
	return yamlBlockSpan(content, parentStart)
}

func yamlDocSpan(content []byte, pos int) []byte {
	lines := bytes.SplitAfter(content, []byte("\n"))
	starts := make([]int, len(lines))
	offset := 0
	for i, l := range lines {
		starts[i] = offset
		offset += len(l)
	}
	isSep := func(i int) bool {
		t := strings.TrimSpace(string(lines[i]))
		return t == "---" || t == "..."
	}
	posLine := len(lines) - 1
	for i := range lines {
		lineEnd := len(content)
		if i+1 < len(starts) {
			lineEnd = starts[i+1]
		}
		if starts[i] <= pos && pos < lineEnd {
			posLine = i
			break
		}
	}
	docStart := 0
	for i := posLine; i >= 0; i-- {
		if isSep(i) {
			docStart = starts[i] + len(lines[i])
			break
		}
	}
	docEnd := len(content)
	for i := posLine + 1; i < len(lines); i++ {
		if isSep(i) {
			docEnd = starts[i]
			break
		}
	}
	if docStart > docEnd {
		return nil
	}
	return content[docStart:docEnd]
}

// MatcherRegistry maps matcher type strings to their Matcher implementations.
type MatcherRegistry struct {
	matchers map[string]Matcher
}

// NewMatcherRegistry returns an empty registry.
func NewMatcherRegistry() *MatcherRegistry {
	return &MatcherRegistry{
		matchers: make(map[string]Matcher),
	}
}

// Register associates a matcher type string with a Matcher implementation.
func (r *MatcherRegistry) Register(matcherType string, m Matcher) {
	r.matchers[matcherType] = m
}

// Get returns the Matcher for the given type string, or nil if none is
// registered.
func (r *MatcherRegistry) Get(matcherType string) Matcher {
	return r.matchers[matcherType]
}

// NewDefaultMatcherRegistry returns a registry pre-populated with every matcher
// nox actually implements. It must stay in lockstep with ValidMatcherTypes: a
// type that validates without a matcher fails the scan loudly, and a type served
// by a do-nothing matcher fails it silently, which is worse.
func NewDefaultMatcherRegistry() *MatcherRegistry {
	r := NewMatcherRegistry()
	r.Register("regex", NewRegexMatcher())
	r.Register("absence", NewAbsenceMatcher())
	r.Register("entropy", &EntropyMatcher{})
	return r
}
