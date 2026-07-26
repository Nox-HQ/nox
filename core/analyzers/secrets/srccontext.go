package secrets

import (
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
)

// This file holds the two source-context filters that decide when a secret rule
// cannot mean what it assumes, and the match is therefore dropped rather than
// downgraded. The precedent is IAC-193 (an Ansible rule on a GitHub Actions
// file): a categorically wrong finding left at a lower severity still costs an
// operator the triage.

// displayTextAttrRE matches an HTML/JSX attribute whose value is text shown to a
// user rather than data the program holds: the hint in an empty input, an
// accessible name, a tooltip, the fallback for an image.
//
// `value=`, `defaultValue=`, `content=` and every other attribute are
// deliberately absent — a private key really can be pasted into one of those,
// and that is a finding.
var displayTextAttrRE = regexp.MustCompile(`(?i)(?:^|[\s{(])(placeholder|aria-label|aria-placeholder|aria-description|alt|title|label)\s*=\s*["']`)

// inDisplayTextAttribute reports whether the finding's match sits inside the
// quoted value of a display-text HTML/JSX attribute.
//
// SEC-004 reported CRITICAL on
//
//	<input placeholder="-----BEGIN RSA PRIVATE KEY-----…" />
//
// which is the instruction telling a user what to paste. The key material is
// theirs and arrives at runtime; the repository holds no secret. Critical is
// the band the shared CI gate fails on, so there is no severity headroom to
// absorb this — it blocks the repository outright.
//
// The check is line-local and requires a tag opener before the attribute, so a
// YAML or JSON key that happens to be called `title` or `label` is untouched.
func inDisplayTextAttribute(content []byte, f *findings.Finding) bool {
	line := lineOf(content, f.Location.StartLine)
	if line == "" || !strings.Contains(line, "<") {
		return false
	}
	// StartColumn is 1-based over the line.
	col := f.Location.StartColumn - 1
	if col < 0 || col > len(line) {
		return false
	}
	for _, loc := range displayTextAttrRE.FindAllStringSubmatchIndex(line, -1) {
		// loc[1] is one past the opening quote of the attribute value.
		open := loc[1]
		if open > len(line) || open == 0 {
			continue
		}
		quote := line[open-1]
		if open > col {
			continue // attribute begins after the match
		}
		end := strings.IndexByte(line[open:], quote)
		if end < 0 {
			// Unterminated on this line: treat the rest of the line as the
			// attribute value, which is what a multi-line JSX attribute is.
			return true
		}
		if col < open+end {
			return true
		}
	}
	return false
}

// configFieldSeparators is the separator alternation shared by the
// Gitleaks-imported "field <separator> value" rules. A rule carrying it does not
// recognise a credential by its shape — it infers one from an ASSIGNMENT: a
// field whose name looks credential-ish, a separator, and a quoted value.
const configFieldSeparators = `(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)`

// configFieldRules is the set of rule IDs whose pattern carries that
// alternation, derived from the rule table itself so an import added there is
// covered without a second list to keep in sync.
var configFieldRules = func() map[string]bool {
	ids := make(map[string]bool)
	for _, r := range builtinSecretRules() {
		if strings.Contains(r.Pattern, configFieldSeparators) {
			ids[r.ID] = true
		}
	}
	return ids
}()

// dropConfigFieldRuleInComment reports whether a config-field rule matched
// entirely inside a comment, where its inference cannot hold.
//
// SEC-240 (Gitleaks `hashicorp-tf-password`) reported high severity on a Go doc
// comment:
//
//	// "bot_token" pops a password input, "imap_password" pops an app-password wizard.
//
// Its separator alternation includes `,`, so the prose parses as `password …`
// `,` `"imap_password"` — a field, a separator, a quoted value. But a comment
// contains prose describing configuration, not configuration, so there is no
// assignment for the rule to have found. Applying a Terraform rule to a Go doc
// comment compounds the error.
//
// This is scoped to the assignment-shaped rules on purpose. The secrets analyzer
// deliberately keeps comment matches for PROVIDER rules, where the token itself
// is the evidence and a credential pasted into a comment is a real leak. A
// credential genuinely left in a comment stays reported here too: the generic
// keyword rules (SEC-005/SEC-080/SEC-112/SEC-402), which are not
// assignment-shaped, still fire on it — see TestConfigFieldRuleNotMatchedInProse.
func dropConfigFieldRuleInComment(lang lexctx.Lang, content []byte, f *findings.Finding) bool {
	if lang == lexctx.LangUnknown || !configFieldRules[f.RuleID] {
		return false
	}
	start := lexctx.LineColToOffset(content, f.Location.StartLine, f.Location.StartColumn)
	end := lexctx.LineColToOffset(content, f.Location.EndLine, f.Location.EndColumn)
	if end <= start {
		end = start + 1
	}
	regions := lexctx.Classify(lang, content)
	if len(regions) == 0 {
		return false
	}
	// EVERY region the match overlaps must be comment. Testing only the two
	// endpoints would accept a match that begins in one comment, crosses code,
	// and ends in the next — and a match leaking out of a comment into code is
	// suspect but not clearly prose, so it is kept.
	overlapped := false
	for _, r := range regions {
		if r.End <= start {
			continue
		}
		if r.Start >= end {
			break
		}
		if r.Kind != lexctx.KindComment {
			return false
		}
		overlapped = true
	}
	return overlapped
}
