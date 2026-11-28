package authz

import (
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
)

// AUTHN-005, THE PROPOSITION.
//
//	A login, sign-in or password-reset path answers a request for an account
//	that does not exist with a message saying so -- "No account is
//	registered with that address", "User not found", "用户不存在",
//	"no_portal_account" -- where an existing account gets a different
//	answer (a wrong-password error, a reset e-mail). The difference tells
//	any caller which accounts exist (CWE-204, observable response
//	discrepancy), which is what credential stuffing and targeted phishing
//	start from.
//
// THE PATH is the enclosing function: its name or the route registered on it
// says login, sign-in, logon, authenticate, forgot, recover, reset or
// password, or it is Spring's loadUserByUsername.
//
// COUNTEREXAMPLES, not reported:
//   - a generic answer: "Invalid email or password", "If that account
//     exists, a reset link was sent";
//   - Spring Security's UsernameNotFoundException, which it replaces with
//     BadCredentialsException by default (hideUserNotFoundExceptions);
//   - the message written to a log rather than the response;
//   - a "not found" outside an authentication path (a profile lookup);
//   - registration ("already exists"), which is out of this claim.
//
// WHERE IT IS REPORTED: at the message.

// EnumerationRuleID is AUTHN-005.
const EnumerationRuleID = "AUTHN-005"

// noAccountRes match the text of a message (a string literal's content) that
// says the account does not exist.
var noAccountRes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:user|username|user name|account|e-?mail(?: address)?|member|customer|login)\b[^.!?\n]{0,40}?\b(?:not found|does ?n[o']t exist|not exist|is not registered|not registered)\b`),
	regexp.MustCompile(`(?i)\bno\s+(?:\w+\s+){0,3}?(?:account|user|member|customer)s?\s*(?:[.!;,]|$|\b(?:found|is|was|with|for|registered|exists?|matching|matches|uses|enrolled|here|under)\b)`),
	regexp.MustCompile(`(?i)\b(?:unknown|no such)\s+(?:user|account|e-?mail|username)\b`),
	regexp.MustCompile(`(?i)\b(?:user|account|e-?mail)_?(?:not_?found|unknown|does_?not_?exist)\b|\bno_\w*account\b`),
	regexp.MustCompile(`(?:用户|账号|账户|帐号|帐户|会员|手机号|邮箱)名?(?:不存在|未注册)`),
}

// genericAnswerRe: the message gives the same answer either way.
var genericAnswerRe = regexp.MustCompile(`(?i)\bor (?:\w+ )?(?:password|e-?mail|username)\b|\bif (?:\w+ ){0,3}(?:exists|is registered)\b`)

// logLineRe: the line writes to a log, not the response.
var logLineRe = regexp.MustCompile(`\b(?:log|logger|LOG|LOGGER|logging|console|_log|slf4j)\s*\.\s*\w+\s*\(|\bSystem\s*\.\s*(?:out|err)\b|^\s*print\s*\(`)

// byIDLookupRe: the account was looked up by an id the caller already holds
// (from a session or a verified token), not by an address or name it typed.
var byIDLookupRe = regexp.MustCompile(`\b(?:findById|getById|findByPk|findOneById|getReferenceById|get_by_id)\s*\(`)

// hiddenByFrameworkRe: Spring Security hides this exception's message.
var hiddenByFrameworkRe = regexp.MustCompile(`\bUsernameNotFoundException\s*\(`)

// authPathWords mark a function or route as an authentication path.
var authPathWords = []string{"login", "logon", "signin", "authenticate", "forgot", "recover", "reset", "password", "passwd", "loaduserbyusername"}

func isAuthPath(name string) bool {
	n := strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 32
		}
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, name)
	for _, w := range authPathWords {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}

// scanEnumeration reports AUTHN-005 in one source file.
func scanEnumeration(path string, lang lexctx.Lang, raw []byte) []findings.Finding {
	if !mayEnumerate(raw) {
		return nil
	}
	code := lexctx.MaskNonCode(lang, raw)
	// A message is often concatenated around a value ("User [" + name +
	// "] not found"), so it is read per line: the line's string literals
	// joined, reported at the line's first literal.
	type lineLits struct {
		first int
		text  strings.Builder
	}
	var order []int
	byLine := map[int]*lineLits{}
	for _, r := range lexctx.Classify(lang, raw) {
		if r.Kind != lexctx.KindString {
			continue
		}
		line := lexctx.LineForOffset(raw, r.Start)
		l := byLine[line]
		if l == nil {
			l = &lineLits{first: r.Start}
			byLine[line] = l
			order = append(order, line)
		}
		l.text.WriteString(string(raw[r.Start:r.End]))
		l.text.WriteByte(' ')
	}
	var out []findings.Finding
	for _, line := range order {
		l := byLine[line]
		lit := l.text.String()
		if !saysNoAccount(lit) || genericAnswerRe.MatchString(lit) {
			continue
		}
		if lineText := lineAround(raw, l.first); logLineRe.MatchString(lineText) || byIDLookupRe.MatchString(lineText) || hiddenByFrameworkRe.Match(raw[max(0, l.first-80):l.first]) {
			continue
		}
		if !isAuthPath(enclosingFunction(lang, raw, code, l.first)) {
			continue
		}
		out = append(out, findings.Finding{
			RuleID:     EnumerationRuleID,
			Severity:   findings.SeverityMedium,
			Confidence: findings.ConfidenceMedium,
			Message:    "An authentication path answers that the account does not exist, so a caller can tell which accounts exist",
			Location:   findings.Location{FilePath: path, StartLine: line, EndLine: line},
			Metadata:   map[string]string{"cwe": "CWE-204", "language": lang.String()},
		})
	}
	return out
}

// mayEnumerate is a cheap prefilter.
func mayEnumerate(raw []byte) bool {
	s := string(raw)
	return strings.Contains(s, "不存在") || strings.Contains(s, "未注册") || strings.Contains(strings.ToLower(s), "account") ||
		strings.Contains(strings.ToLower(s), "not found") || strings.Contains(strings.ToLower(s), "exist") ||
		strings.Contains(strings.ToLower(s), "registered") || strings.Contains(strings.ToLower(s), "unknown") ||
		strings.Contains(strings.ToLower(s), "no user") || strings.Contains(strings.ToLower(s), "no such")
}

func saysNoAccount(lit string) bool {
	for _, re := range noAccountRes {
		if re.MatchString(lit) {
			return true
		}
	}
	return false
}

func lineAround(raw []byte, at int) string {
	s := strings.LastIndexByte(string(raw[:at]), '\n') + 1
	e := strings.IndexByte(string(raw[at:]), '\n')
	if e < 0 {
		return string(raw[s:])
	}
	return string(raw[s : at+e])
}

// enclosingFunction names the function the offset is in, with the route
// registered on it when one is written beside it: "login", "POST /forgot".
// It returns "" when no enclosing function is found.
func enclosingFunction(lang lexctx.Lang, raw, code []byte, at int) string {
	if lang == lexctx.LangPython {
		return pyEnclosing(raw, code, at)
	}
	return braceEnclosing(raw, code, at)
}

var (
	enumPyDefRe  = regexp.MustCompile(`(?m)^([ \t]*)(?:async[ \t]+)?def[ \t]+(\w+)`)
	routeStrRe   = regexp.MustCompile(`["'\x60](/[^"'\x60\s]*)["'\x60]`)
	arrowNameRe  = regexp.MustCompile(`(\w+)\s*[=:]\s*(?:async\s*)?(?:\([^()]*\)|\w+)\s*=>\s*$`)
	blockWords   = map[string]bool{"if": true, "for": true, "while": true, "switch": true, "catch": true, "synchronized": true, "foreach": true, "with": true, "function": true, "when": true}
	javaMethodRe = regexp.MustCompile(`\)\s*(?:(?:throws|:)\s*[^(){};=]*)?$`)
)

// pyEnclosing finds the def above at with less indentation than at's line,
// and the route strings in the decorators directly above it.
func pyEnclosing(raw, code []byte, at int) string {
	lineStart := strings.LastIndexByte(string(raw[:at]), '\n') + 1
	indent := 0
	for lineStart+indent < len(raw) && (raw[lineStart+indent] == ' ' || raw[lineStart+indent] == '\t') {
		indent++
	}
	defs := enumPyDefRe.FindAllSubmatchIndex(code[:lineStart], -1)
	for i := len(defs) - 1; i >= 0; i-- {
		d := defs[i]
		if d[3]-d[2] >= indent {
			continue
		}
		name := string(code[d[4]:d[5]])
		// Decorators: the lines directly above the def that start with @.
		above := strings.Split(string(raw[:d[0]]), "\n")
		for j := len(above) - 2; j >= 0 && j >= len(above)-6; j-- {
			t := strings.TrimSpace(above[j])
			if !strings.HasPrefix(t, "@") {
				break
			}
			if m := routeStrRe.FindStringSubmatch(t); m != nil {
				name += " " + m[1]
			}
		}
		return name
	}
	return ""
}

// braceEnclosing walks out through the blocks around at and names the first
// one that is a function body: `name(...) {`, `function name(...) {`,
// `name = (...) => {`, or a callback passed to a route registration
// (`router.post('/login', async (req, res) => {`). Control blocks, Java
// lambdas and anonymous callbacks are walked through.
func braceEnclosing(raw, code []byte, at int) string {
	pos := at
	for pos > 0 {
		open := openingBrace(code, pos)
		if open < 0 {
			return ""
		}
		before := strings.TrimRight(string(code[max(0, open-400):open]), " \t\r\n")
		rawBefore := string(raw[max(0, open-400):open])
		switch {
		case strings.HasSuffix(before, "=>"):
			if m := arrowNameRe.FindStringSubmatch(before); m != nil {
				return m[1] + routeNear(rawBefore)
			}
			if r := routeNear(lastLines(rawBefore, 2)); r != "" {
				return r
			}
		case javaMethodRe.MatchString(before):
			if name := nameBeforeParams(before); name != "" && !blockWords[name] {
				// The route annotation or registration just above the method.
				return name + routeNear(lastLines(rawBefore, 4))
			}
		}
		pos = open
	}
	return ""
}

// openingBrace returns the offset of the '{' that opens the block containing
// pos, or -1.
func openingBrace(code []byte, pos int) int {
	depth := 0
	for i := pos - 1; i >= 0; i-- {
		switch code[i] {
		case '}':
			depth++
		case '{':
			if depth == 0 {
				return i
			}
			depth--
		}
	}
	return -1
}

// nameBeforeParams returns the identifier before the parameter list that
// ends s (s ends with ')' and optionally a throws clause or return type).
func nameBeforeParams(s string) string {
	end := strings.LastIndexByte(s, ')')
	if end < 0 {
		return ""
	}
	depth := 0
	for i := end; i >= 0; i-- {
		switch s[i] {
		case ')':
			depth++
		case '(':
			depth--
			if depth == 0 {
				j := i
				for j > 0 && (s[j-1] == ' ' || s[j-1] == '\t') {
					j--
				}
				k := j
				for k > 0 && isIdentByte(s[k-1]) {
					k--
				}
				return s[k:j]
			}
		}
	}
	return ""
}

// routeNear returns " /path" for the last route path written in s, or "".
func routeNear(s string) string {
	m := routeStrRe.FindAllStringSubmatch(s, -1)
	if len(m) == 0 {
		return ""
	}
	return " " + m[len(m)-1][1]
}

func lastLines(s string, n int) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '\n' {
			n--
			if n == 0 {
				return s[i+1:]
			}
		}
	}
	return s
}
