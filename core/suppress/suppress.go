// Package suppress provides inline suppression detection for nox findings.
// Developers can suppress specific rules by adding comments like:
//
//	// nox:ignore SEC-001 -- false positive in test
//	# nox:ignore SEC-001,SEC-002
//	<!-- nox:ignore AI-001 -->
//	/* nox:ignore IAC-001 */
//	-- nox:ignore DEP-001 -- known issue expires:2025-12-31
//
// `nox:disable` is accepted as an alias for `nox:ignore` to match the
// convention used by gosec (`#nosec`), staticcheck, and golangci-lint
// (`//nolint:RULE`) so muscle memory carries over. The two forms are
// fully interchangeable.
package suppress

import (
	"bufio"
	"bytes"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/nox-hq/nox/core/lexctx"
)

// Suppression represents a single inline suppression directive found in source.
type Suppression struct {
	RuleIDs  []string
	FilePath string
	Line     int // the line the suppression applies to
	Reason   string
	Expires  *time.Time

	// InvalidExpiry holds the date text of an expires: directive that could
	// not be parsed. It is set instead of Expires, never alongside it.
	//
	// A malformed expiry must never be treated as "no expiry". The parse
	// failure used to be discarded while the expires: text was still stripped
	// from the reason, so a typo like expires:2026-13-01 silently produced a
	// PERMANENT waiver that looked accepted. Suppressions carrying this field
	// do not match, so the finding is reported — failing toward showing
	// findings rather than hiding them — and the caller reports it.
	InvalidExpiry string

	// DocExample marks a directive written inside a fenced code block in a
	// markdown file — i.e. documentation showing what a nox:ignore looks like,
	// not a waiver an operator expects to apply. It changes nothing about
	// matching: such a directive still suppresses a real finding on its target
	// line, exactly as before. It only tells the caller not to report it as an
	// unused waiver, because prose demonstrating the syntax waives nothing by
	// design and that report would be pure noise. nox's own README trips this.
	DocExample bool
}

// markdownExts are the file types whose fenced code blocks hold illustrative
// directives rather than operative ones.
var markdownExts = map[string]bool{".md": true, ".markdown": true, ".mdx": true}

// isFence reports whether a trimmed line opens or closes a fenced code block.
func isFence(trimmed string) bool {
	return strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~")
}

// suppressionRE matches nox:ignore / nox:disable directives in any
// comment style. The `(?:ignore|disable)` alternation makes both
// keywords equivalent at the regex level — every downstream consumer
// just sees a Suppression record with no notion of which spelling was
// used in source.
var suppressionRE = regexp.MustCompile(
	`(?://|#|--|/\*|<!--)\s*nox:(?:ignore|disable)\s+([\w-]+(?:,[\w-]+)*)\s*(?:--\s*(.*))?`,
)

// expiresRE extracts an expires:YYYY-MM-DD from the reason text.
var expiresRE = regexp.MustCompile(`expires:(\d{4}-\d{2}-\d{2})`)

// stringSubmatches rebuilds FindStringSubmatch's []string result from the
// index pairs FindStringSubmatchIndex returns, so the match position is
// available (for the string-literal test) without scanning the line twice.
// A group that did not participate yields "".
func stringSubmatches(s string, loc []int) []string {
	out := make([]string, len(loc)/2)
	for i := range out {
		if loc[2*i] >= 0 {
			out[i] = s[loc[2*i]:loc[2*i+1]]
		}
	}
	return out
}

// ruleIDToken matches a single rule identifier in the space-separated form
// (`nox:ignore SEC-161 SEC-162 -- reason`). A hyphen is required so a prose
// word cannot be mistaken for another rule ID; every catalog rule is
// PREFIX-NUMBER, and the comma-separated form — which needs no such guard
// because its shape is unambiguous — remains the documented spelling.
var ruleIDToken = regexp.MustCompile(`^\w+-[\w-]+`)

// commentStarters are the comment openers suppressionRE recognises, longest
// first so `<!--` is not mistaken for `--`.
var commentStarters = []string{"<!--", "/*", "//", "--", "#"}

// nestedInComment reports whether a directive sits inside a comment that
// already began earlier on the line — which makes it an example rather than a
// waiver.
//
// This package's own doc comment lists every supported spelling as an indented
// code block (`//\t// nox:ignore SEC-001 -- …`), and comments describing the
// parser quote directives inline. Both were read as live waivers, so once the
// unused-waiver check started sweeping files with no findings, this one file
// reported six waivers that never existed.
//
// The test is positional and needs no language knowledge: if the line's first
// non-whitespace content opens a comment and the directive's own marker is not
// that opener, the directive is written *inside* prose. A real waiver either
// starts its line's comment or follows code (`foo() // nox:ignore …`), and
// both keep matchStart at the comment opener.
func nestedInComment(line string, matchStart int) bool {
	trimmed := strings.TrimLeft(line, " \t")
	indent := len(line) - len(trimmed)
	for _, m := range commentStarters {
		if strings.HasPrefix(trimmed, m) {
			return matchStart > indent
		}
	}
	return false
}

// directiveTailOK reports whether what follows a directive's rule IDs is
// consistent with a directive rather than prose.
//
// Accepted: nothing, a comment terminator, a `--` reason, or further
// space-separated rule IDs before either of those. Anything else means the
// line is describing the syntax, not using it.
func directiveTailOK(rest string) bool {
	rest = strings.TrimSpace(rest)
	for {
		rest = strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(rest, "*/"), "-->"))
		if rest == "" {
			return true
		}
		if strings.HasPrefix(rest, "--") {
			// The reason separator (and `-->`, already trimmed above).
			return true
		}
		tok := ruleIDToken.FindString(rest)
		if tok == "" {
			return false
		}
		rest = strings.TrimSpace(rest[len(tok):])
	}
}

// ScanForSuppressions scans file content for nox:ignore directives and returns
// all suppressions found. Each suppression targets either the same line
// (trailing comment) or the next non-blank, non-comment line.
func ScanForSuppressions(content []byte, filePath string) []Suppression {
	var result []Suppression

	scanner := bufio.NewScanner(bytes.NewReader(content))
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	// Fenced code blocks in markdown hold directives that illustrate the syntax
	// rather than waive anything; track them so the caller can tell the two apart.
	isMarkdown := markdownExts[strings.ToLower(filepath.Ext(filePath))]
	inFence := false

	// A directive written inside a string literal is a program printing the
	// syntax, not a waiver on that line — nox's own pre-commit hook installer
	// contains `echo "nox: use '// nox:ignore RULE-ID -- reason'"`, which was
	// read as waiving a rule called RULE-ID.
	//
	// Deliberately classified one line at a time rather than over the whole
	// file: a string that opens and closes on the directive's own line is
	// unambiguous, while a region spanning many lines is usually an artifact
	// (an unterminated or raw string) and treating a directive inside one as
	// prose would silently drop a real waiver. Only a positive, single-line
	// string identification suppresses the directive.
	lang := lexctx.LangFromPath(filePath)

	for i, line := range lines {
		lineNum := i + 1
		if isMarkdown && isFence(strings.TrimSpace(line)) {
			inFence = !inFence
		}
		loc := suppressionRE.FindStringSubmatchIndex(line)
		if loc == nil {
			continue
		}
		match := stringSubmatches(line, loc)

		if lexctx.KindAt(lexctx.Classify(lang, []byte(line)), loc[0]) == lexctx.KindString {
			continue
		}

		// A directive's grammar is `nox:ignore <IDs> [-- reason]`: after the
		// rule IDs the line must end, close the comment, or introduce a reason
		// with `--`. Free prose after the IDs means the text is *describing* a
		// directive rather than issuing one — a doc comment that wrapped so
		// that "…holds no nox:ignore comments, so nothing was missed" began a
		// line was read as waiving a rule named "comments". Because a waiver
		// that matches nothing is reported, that produced a false "dead waiver"
		// degradation against correct code.
		if !directiveTailOK(line[loc[1]:]) {
			continue
		}

		ruleIDs := strings.Split(match[1], ",")
		reason := strings.TrimSpace(match[2])

		// Clean up reason: remove closing comment markers. HTML comments
		// are tricky — `<!-- nox:ignore X -->` leaves `-->` partially in
		// the reason capture because the `(?:--\s*(.*))?` group reads
		// the leading `--` of `-->` as the reason separator. Strip in
		// a loop so we catch nested/whitespaced variants like `*/  ` or
		// `--> /* trailing */`.
		for {
			prev := reason
			reason = strings.TrimSuffix(reason, "*/")
			reason = strings.TrimSuffix(reason, "-->")
			// HTML-comment leftover: after `--` was consumed as the
			// reason separator, the `>` sits alone. Only strip it when
			// the source line was an HTML comment, to avoid clobbering
			// a legitimate trailing `>` in a non-HTML reason (e.g. a
			// version range note).
			if strings.HasSuffix(reason, ">") && strings.Contains(line, "<!--") {
				reason = strings.TrimSuffix(reason, ">")
			}
			reason = strings.TrimSpace(reason)
			if reason == prev {
				break
			}
		}

		// Parse expiration from reason.
		var expires *time.Time
		var invalidExpiry string
		if em := expiresRE.FindStringSubmatch(reason); em != nil {
			if t, err := time.Parse("2006-01-02", em[1]); err == nil {
				expires = &t
			} else {
				invalidExpiry = em[1]
			}
			reason = strings.TrimSpace(expiresRE.ReplaceAllString(reason, ""))
		}

		// Determine target line: if the line is only a comment (suppression
		// directive), it applies to the next non-blank line. If the suppression
		// is a trailing comment on a code line, it applies to the same line.
		targetLine := lineNum
		trimmed := strings.TrimSpace(line)
		if isOnlyComment(trimmed) {
			targetLine = nextNonBlankLine(lines, i)
		}

		result = append(result, Suppression{
			RuleIDs:       ruleIDs,
			FilePath:      filePath,
			Line:          targetLine,
			Reason:        reason,
			Expires:       expires,
			InvalidExpiry: invalidExpiry,
			DocExample:    (isMarkdown && inFence) || nestedInComment(line, loc[0]),
		})
	}

	return result
}

// MatchesFinding returns true if this suppression applies to the given rule
// and line, considering expiration.
func (s Suppression) MatchesFinding(ruleID string, line int, now time.Time) bool {
	if s.Line != line {
		return false
	}
	// An expiry the operator wrote but nox could not parse is not an absent
	// expiry. Refuse to suppress rather than silently making the waiver
	// permanent.
	if s.InvalidExpiry != "" {
		return false
	}
	if s.Expires != nil && now.After(*s.Expires) {
		return false
	}
	for _, id := range s.RuleIDs {
		if id == ruleID {
			return true
		}
	}
	return false
}

// isOnlyComment returns true if the line consists entirely of a comment.
func isOnlyComment(trimmed string) bool {
	for _, prefix := range []string{"//", "#", "--", "/*", "<!--"} {
		if strings.HasPrefix(trimmed, prefix) {
			return true
		}
	}
	return false
}

// nextNonBlankLine returns the 1-based line number of the next non-blank,
// non-comment line after index i. If none exists, returns i+2 (the line
// immediately after the comment).
func nextNonBlankLine(lines []string, i int) int {
	for j := i + 1; j < len(lines); j++ {
		trimmed := strings.TrimSpace(lines[j])
		if trimmed == "" {
			continue
		}
		if isOnlyComment(trimmed) && suppressionRE.MatchString(trimmed) {
			continue
		}
		return j + 1
	}
	return i + 2
}
