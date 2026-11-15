package engine

import (
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/taint"
)

// A host allowlist is the SSRF defence written as a guard rather than a call:
//
//	const u = new URL(process.env.TARGET_URL);
//	if (u.protocol !== 'https:' || u.hostname !== 'raw.githubusercontent.com') {
//	  process.exit(2);
//	}
//	await fetch(u.href);
//
// No sanitizer is called, so the value reaching fetch was never "cleared", and
// TAINT-006 reported every such fetch exactly as it reported the unguarded one
// (Nox-HQ/nox#1096: nox-hq.dev's sync-plugins.mjs, and the same shape in Python
// and in a shell `case`). What makes the guard a defence is not that it reads
// the value but two things together:
//
//  1. its condition pins the HOST to literals: every term compares the parsed
//     URL's host (hostname/host/origin/netloc) or scheme against a string
//     literal, at least one of them the host, joined by OR, so the branch runs
//     whenever the host is anything else; and
//  2. that branch does not fall through: its last statement exits, throws,
//     raises or returns.
//
// Either alone is not a defence. A guard whose branch logs and continues
// validates nothing, and a condition that compares the host to a variable
// pins it to whatever the variable holds. Both are required here, and a
// comparison this does not recognize (an allowlist Set, a regex test) leaves
// the finding as it was: unrecognized is not refuted.
//
// It clears SSRF only. A host pinned to a literal says nothing about the path a
// shell command interpolates or the query an SQL statement concatenates.

// hostAllowlistsFor returns the host allowlist guards in content.
func hostAllowlistsFor(lang lexctx.Lang, content []byte) []taint.HostAllowlist {
	lines := strings.Split(string(content), "\n")
	switch lang {
	case lexctx.LangJavaScript:
		return jsHostAllowlists(lines)
	case lexctx.LangPython:
		return pyHostAllowlists(lines)
	case lexctx.LangShell:
		return shellHostAllowlists(lines)
	}
	return nil
}

var (
	// A string literal in the languages here: '…', "…" or a template with no
	// interpolation. Escapes inside are not needed to recognize a host.
	litRe = `(?:'[^'\\]*'|"[^"\\]*"|` + "`[^`$\\\\]*`" + `)`

	jsHostTermRe = regexp.MustCompile(`^([A-Za-z_$][\w$]*)\.(hostname|host|origin|protocol)\s*!==?\s*` + litRe + `$`)
	jsLitFirstRe = regexp.MustCompile(`^` + litRe + `\s*!==?\s*([A-Za-z_$][\w$]*)\.(hostname|host|origin|protocol)$`)
	jsTermRe     = regexp.MustCompile(`^\s*(?:return\b|throw\b|process\.exit\s*\(|Deno\.exit\s*\(|exit\s*\()`)

	pyHostTermRe = regexp.MustCompile(`^([A-Za-z_]\w*)\.(hostname|netloc|host|scheme)\s*!=\s*` + litRe + `$`)
	pyHostInRe   = regexp.MustCompile(`^([A-Za-z_]\w*)\.(hostname|netloc|host|scheme)\s+not\s+in\s+[\(\[\{]\s*(` + litRe + `(?:\s*,\s*` + litRe + `)*)\s*,?\s*[\)\]\}]$`)
	pyTermRe     = regexp.MustCompile(`^\s*(?:sys\.exit\s*\(|exit\s*\(|os\._exit\s*\(|raise\b|return\b|abort\s*\()`)

	shCaseRe    = regexp.MustCompile(`^\s*case\s+"?\$\{?([A-Za-z_]\w*)\}?"?\s+in\s*$`)
	shArmRe     = regexp.MustCompile(`^\s*\(?([^)]*)\)\s*(.*)$`)
	shFixedHost = regexp.MustCompile(`^['"]?https?://[A-Za-z0-9.\-]+(?::\d+)?/`)
	shExitRe    = regexp.MustCompile(`(?:^|[;\s])(?:exit|return)\b`)
)

// splitTop splits s on sep outside parentheses and string literals.
func splitTop(s, sep string) []string {
	var out []string
	depth, start := 0, 0
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"' || c == '`':
			quote = c
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			depth--
		case depth == 0 && strings.HasPrefix(s[i:], sep):
			out = append(out, s[start:i])
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	return append(out, s[start:])
}

// trimParens strips balanced outer parentheses.
func trimParens(s string) string {
	s = strings.TrimSpace(s)
	for len(s) >= 2 && s[0] == '(' && s[len(s)-1] == ')' && matchingParen(s, 0) == len(s)-1 {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
}

// matchingParen returns the index of the ')' closing the '(' at open, or -1.
func matchingParen(s string, open int) int {
	depth := 0
	var quote byte
	for i := open; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"' || c == '`':
			quote = c
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// pinnedVar returns the variable whose host every term of cond pins to a
// literal. match returns a term's variable and property, or ok=false.
func pinnedVar(terms []string, match func(string) (v, prop string, ok bool), hostProps map[string]bool) (string, bool) {
	var v string
	var host bool
	for _, t := range terms {
		tv, prop, ok := match(trimParens(t))
		if !ok || (v != "" && tv != v) {
			return "", false
		}
		v = tv
		host = host || hostProps[prop]
	}
	return v, host && v != ""
}

var jsHostProps = map[string]bool{"hostname": true, "host": true, "origin": true}

func jsTerm(t string) (v, prop string, ok bool) {
	if m := jsHostTermRe.FindStringSubmatch(t); m != nil {
		return m[1], m[2], true
	}
	if m := jsLitFirstRe.FindStringSubmatch(t); m != nil {
		return m[1], m[2], true
	}
	return "", "", false
}

func jsHostAllowlists(lines []string) []taint.HostAllowlist {
	var out []taint.HostAllowlist
	for i, line := range lines {
		code := strings.TrimSpace(line)
		code = strings.TrimSpace(strings.TrimPrefix(code, "}"))
		code = strings.TrimSpace(strings.TrimPrefix(code, "else"))
		if !strings.HasPrefix(code, "if") {
			continue
		}
		rest := strings.TrimSpace(code[2:])
		if !strings.HasPrefix(rest, "(") {
			continue
		}
		closeAt := matchingParen(rest, 0)
		if closeAt < 0 {
			continue
		}
		v, ok := pinnedVar(splitTop(rest[1:closeAt], "||"), jsTerm, jsHostProps)
		if !ok {
			continue
		}
		after := strings.TrimSpace(rest[closeAt+1:])
		end, terminates := jsBranchTerminates(lines, i, after)
		if terminates {
			out = append(out, taint.HostAllowlist{Line: end + 1, Var: v})
		}
	}
	return out
}

// jsBranchTerminates reports whether the branch that follows an if's condition
// ends by leaving, and the 0-based line it ends on. after is the text after
// the condition's closing parenthesis.
func jsBranchTerminates(lines []string, at int, after string) (int, bool) {
	if !strings.HasPrefix(after, "{") {
		// Unbraced: the single statement on this line or the next.
		if after != "" {
			return at, jsTermRe.MatchString(after)
		}
		if at+1 < len(lines) {
			return at + 1, jsTermRe.MatchString(lines[at+1])
		}
		return at, false
	}
	depth := 0
	last := ""
	for j := at; j < len(lines); j++ {
		seg := lines[j]
		if j == at {
			seg = after
		}
		for k := 0; k < len(seg); k++ {
			switch seg[k] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					body := strings.TrimSpace(seg[:k])
					if body != "" && body != "{" {
						last = body
					}
					return j, jsTermRe.MatchString(strings.TrimPrefix(last, "{"))
				}
			}
		}
		if s := strings.TrimSpace(seg); s != "" && s != "{" && !strings.HasPrefix(s, "//") {
			last = s
		}
	}
	return at, false
}

var pyHostProps = map[string]bool{"hostname": true, "netloc": true, "host": true}

func pyTerm(t string) (v, prop string, ok bool) {
	if m := pyHostTermRe.FindStringSubmatch(t); m != nil {
		return m[1], m[2], true
	}
	if m := pyHostInRe.FindStringSubmatch(t); m != nil {
		return m[1], m[2], true
	}
	return "", "", false
}

var pyIfRe = regexp.MustCompile(`^(\s*)(?:el)?if\s+(.+?):\s*(?:#.*)?$`)

func pyHostAllowlists(lines []string) []taint.HostAllowlist {
	var out []taint.HostAllowlist
	for i, line := range lines {
		m := pyIfRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		v, ok := pinnedVar(splitTop(m[2], " or "), pyTerm, pyHostProps)
		if !ok {
			continue
		}
		indent := len(m[1])
		last, lastLine := "", -1
		for j := i + 1; j < len(lines); j++ {
			s := strings.TrimSpace(lines[j])
			if s == "" || strings.HasPrefix(s, "#") {
				continue
			}
			if len(lines[j])-len(strings.TrimLeft(lines[j], " \t")) <= indent {
				break
			}
			last, lastLine = s, j
		}
		if lastLine >= 0 && pyTermRe.MatchString(last) {
			out = append(out, taint.HostAllowlist{Line: lastLine + 1, Var: v})
		}
	}
	return out
}

// shellHostAllowlists recognizes
//
//	case "$url" in
//	  https://raw.githubusercontent.com/*) ;;
//	  *) echo "bad host" >&2; exit 2 ;;
//	esac
//
// Every arm but the default must match only URLs on a literal host (the host
// is followed by '/', so `https://good.example*` — which also matches
// good.example.attacker.net — does not count), and the default arm must exit.
func shellHostAllowlists(lines []string) []taint.HostAllowlist {
	var out []taint.HostAllowlist
	for i := 0; i < len(lines); i++ {
		m := shCaseRe.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		v := m[1]
		var (
			armsOK      = true
			defaultExit bool
			sawFixed    bool
			esac        = -1
			inDefault   bool
		)
		for j := i + 1; j < len(lines); j++ {
			s := strings.TrimSpace(lines[j])
			if s == "esac" || strings.HasPrefix(s, "esac ") || strings.HasPrefix(s, "esac;") {
				esac = j
				break
			}
			if s == "" || strings.HasPrefix(s, "#") {
				continue
			}
			if am := shArmRe.FindStringSubmatch(s); am != nil && !strings.HasPrefix(s, ";;") && !inBodyLine(s) {
				pat := strings.TrimSpace(am[1])
				body := am[2]
				inDefault = pat == "*"
				if inDefault {
					defaultExit = defaultExit || shExitRe.MatchString(body)
				} else {
					for _, alt := range strings.Split(pat, "|") {
						if !shFixedHost.MatchString(strings.TrimSpace(alt)) {
							armsOK = false
						}
					}
					sawFixed = true
				}
				continue
			}
			if inDefault && shExitRe.MatchString(s) {
				defaultExit = true
			}
		}
		if esac >= 0 && armsOK && sawFixed && defaultExit {
			out = append(out, taint.HostAllowlist{Line: esac + 1, Var: v})
		}
		if esac > i {
			i = esac
		}
	}
	return out
}

// inBodyLine reports whether s is an ordinary command line inside an arm
// rather than a new pattern: a pattern line's ')' precedes any space.
func inBodyLine(s string) bool {
	p := strings.IndexByte(s, ')')
	sp := strings.IndexAny(s, " \t")
	return p < 0 || (sp >= 0 && sp < p && !strings.HasPrefix(s, "("))
}

// attachHostAllowlists gives each guard to the unit holding the closest
// statement at or before it: the guard's own scope, whose assignment of the
// checked value precedes the check.
func attachHostAllowlists(units []taint.Unit, guards []taint.HostAllowlist) {
	for _, g := range guards {
		best, bestLine := -1, 0
		for ui := range units {
			for _, st := range units[ui].Stmts {
				if st.Line <= g.Line && st.Line > bestLine {
					best, bestLine = ui, st.Line
				}
			}
		}
		if best >= 0 {
			units[best].HostAllowlists = append(units[best].HostAllowlists, g)
		}
	}
}

// urlParsers are calls whose result is the parsed form of their argument, so a
// guard on the result pins the argument's host too (`p = urlparse(u)` then
// `if p.hostname != …: sys.exit()` then `urlopen(u)`).
var urlParsers = map[string]bool{
	"URL": true, "new URL": true, "URL.parse": true, "url.parse": true,
	"urlparse": true, "urlsplit": true, "parse.urlparse": true, "parse.urlsplit": true,
	"urllib.parse.urlparse": true, "urllib.parse.urlsplit": true,
}

// hostAllowlistClears returns the variables whose SSRF taint the guard clears:
// the checked variable, and the variable it was parsed from.
func hostAllowlistClears(unit *taint.Unit, g taint.HostAllowlist) []string {
	out := []string{g.Var}
	var assign *taint.Statement
	for i := range unit.Stmts {
		st := &unit.Stmts[i]
		if st.Line < g.Line && st.Assigns == g.Var {
			assign = st
		}
	}
	if assign == nil {
		return out
	}
	for _, c := range assign.Calls {
		if urlParsers[c] || urlParsers[strings.TrimPrefix(c, "new ")] {
			out = append(out, assign.Reads...)
			break
		}
	}
	return out
}
