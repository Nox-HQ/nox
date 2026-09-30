package engine

import (
	"regexp"
	"strings"
)

// Branch model for the Java extractor.
//
// Before this, Java had none: a statement inside an if, else, loop or switch
// was an unconditional strong update (the last assignment won), and a
// brace-less branch -- `if (c) bar = "safe"; else bar = param;`, the form most
// short Java branches take -- was skipped whole, because its line starts with
// `if`. The first cost recall (a flow on one arm was overwritten by the other),
// the second cost both.
//
// Now, as for Python (pydead.go):
//
//   - a statement in a branch body is Conditional (a weak update);
//   - a brace-less branch's statement is extracted and treated the same way;
//   - an if/else-if/else arm, a switch case, or a ternary whose condition is a
//     constant is resolved: the arm that cannot run is dropped, the one that
//     must run is not conditional.
//
// Constants use the Python evaluator (pyconst.go) on Java syntax translated to
// it -- `&&`, `||`, `!`, `s.charAt(i)`, `a.equals(b)`, `s.contains(x)` -- and
// the same refuse-rather-than-guess contract: an operand that is not a literal
// or a local the file assigns exactly once makes the condition unknown, and an
// unknown condition changes nothing.

// javaBlock is one open brace block the branch model cares about.
type javaBlock struct {
	interior int // brace depth of the block's body
	state    branchState
	sw       *javaSwitch // non-nil for a switch body
}

// javaSwitch tracks a switch body's cases.
type javaSwitch struct {
	subject   pyValue
	subjectOK bool
	decided   bool // a case was taken and ended with break: later cases are dead
	unknown   bool // an earlier case could not be resolved
	cur       branchState
	body      bool // the current case has statements
	ended     bool // the current case body ended with break/return/throw
	labels    []string
}

// javaBranches is the per-file branch state the Java extractor consults.
type javaBranches struct {
	blocks []javaBlock
	chains map[int]*pyChain // if/else chains by brace depth
	env    pyConstEnv
	single map[string]bool
	// pending applies to the next statement: `if (c)` or `else` with the
	// statement on the following line.
	pending *branchState
}

var (
	javaCaseLabel  = regexp.MustCompile(`^(?:case\s+(.+?)|default)\s*:\s*(.*)$`)
	javaCharLit    = regexp.MustCompile(`'(\\?.)'`)
	javaCharAt     = regexp.MustCompile(`\.\s*charAt\s*\(\s*(-?\d+)\s*\)`)
	javaEquals     = regexp.MustCompile(`([\w."]+)\s*\.\s*equals\s*\(\s*([^()]+?)\s*\)`)
	javaContains   = regexp.MustCompile(`([\w."]+)\s*\.\s*contains\s*\(\s*([^()]+?)\s*\)`)
	javaAssignName = regexp.MustCompile(`(?:^|[\s,(])([A-Za-z_]\w*)\s*(?:[-+*/%&|^]|<<|>>|>>>)?=[^=]`)
	javaIncDec     = regexp.MustCompile(`([A-Za-z_]\w*)\s*(?:\+\+|--)|(?:\+\+|--)\s*([A-Za-z_]\w*)`)
	javaForVar     = regexp.MustCompile(`\bfor\s*\(\s*(?:final\s+)?[\w<>\[\],.? ]+?\s+([A-Za-z_]\w*)\s*[:=]`)
)

func newJavaBranches(lines []logicalLine) *javaBranches {
	return &javaBranches{chains: map[int]*pyChain{}, env: pyConstEnv{}, single: javaSingleAssigned(lines)}
}

// javaSingleAssigned returns the names the file assigns exactly once and never
// changes otherwise (compound assignment, ++/--, a for variable).
func javaSingleAssigned(lines []logicalLine) map[string]bool {
	count, never := map[string]int{}, map[string]bool{}
	for _, ll := range lines {
		code := ll.code
		for _, m := range javaAssignName.FindAllStringSubmatch(code, -1) {
			count[m[1]]++
		}
		for _, m := range pyAugmentedAnywhere.FindAllStringSubmatch(code, -1) {
			never[m[1]] = true
		}
		for _, m := range javaIncDec.FindAllStringSubmatch(code, -1) {
			never[m[1]+m[2]] = true
		}
		for _, m := range javaForVar.FindAllStringSubmatch(code, -1) {
			never[m[1]] = true
		}
	}
	out := map[string]bool{}
	for n, c := range count {
		if c == 1 && !never[n] {
			out[n] = true
		}
	}
	return out
}

// toPyExpr translates the Java expression subset the evaluator understands.
func toPyExpr(expr string) string {
	e := javaCharLit.ReplaceAllString(expr, `"$1"`)
	e = javaCharAt.ReplaceAllString(e, "[$1]")
	e = javaEquals.ReplaceAllString(e, "($1 == $2)")
	e = javaContains.ReplaceAllString(e, "($2 in $1)")
	// PHP and JavaScript's strict comparisons compare like == on the
	// literals the evaluator accepts.
	e = strings.NewReplacer("===", "==", "!==", "!=").Replace(e)
	e = strings.NewReplacer("&&", " and ", "||", " or ", "!=", "\x00", "!", " not ").Replace(e)
	return strings.ReplaceAll(e, "\x00", "!=")
}

func (b *javaBranches) eval(expr string) (pyValue, bool) {
	return evalPyConst(toPyExpr(expr), b.env)
}

// enter pops the blocks the line at depthNow is no longer inside.
func (b *javaBranches) enter(depthNow int) {
	for len(b.blocks) > 0 && b.blocks[len(b.blocks)-1].interior > depthNow {
		b.blocks = b.blocks[:len(b.blocks)-1]
	}
	for d := range b.chains {
		if d > depthNow {
			delete(b.chains, d)
		}
	}
}

// state is the combined state of the enclosing blocks: dead if any is dead,
// maybe if any is maybe, taken otherwise.
func (b *javaBranches) state() branchState {
	st := branchTaken
	for _, blk := range b.blocks {
		s := blk.state
		if blk.sw != nil {
			s = blk.sw.cur
		}
		switch s {
		case branchDead:
			return branchDead
		case branchMaybe:
			st = branchMaybe
		}
	}
	return st
}

func (b *javaBranches) innermostSwitch() *javaSwitch {
	if n := len(b.blocks); n > 0 {
		return b.blocks[n-1].sw
	}
	return nil
}

// javaHeader is a control-flow header parsed from a structural line.
type javaHeader struct {
	kind   string // "if", "elseif", "else", "loop", "switch", "other"
	cond   string // raw condition text
	rest   string // the statement after a brace-less header ("" if none)
	opens  bool   // the line ends by opening a block
	restAt int    // offset of rest within the logical line
}

// parseJavaHeader reads `[}] else if (c) stmt`, `if (c) {`, `for (...) stmt`,
// `switch (x) {` and the like. Offsets are into ll.code/ll.raw.
func parseJavaHeader(ll logicalLine) (javaHeader, bool) {
	code := ll.code
	i := 0
	for i < len(code) && (code[i] == ' ' || code[i] == '\t' || code[i] == '}') {
		i++
	}
	rest := code[i:]
	h := javaHeader{}
	switch {
	case strings.HasPrefix(rest, "else if") || strings.HasPrefix(rest, "else  if"):
		h.kind = "elseif"
		i += strings.Index(rest, "if") + 2
	case strings.HasPrefix(rest, "elseif"):
		// PHP's one-word form.
		h.kind = "elseif"
		i += len("elseif")
	case strings.HasPrefix(rest, "else"):
		h.kind = "else"
		i += len("else")
	case strings.HasPrefix(rest, "if"):
		h.kind = "if"
		i += 2
	case strings.HasPrefix(rest, "for") || strings.HasPrefix(rest, "while"):
		h.kind = "loop"
		i += strings.IndexAny(rest, " (")
	case strings.HasPrefix(rest, "switch"):
		h.kind = "switch"
		i += len("switch")
	default:
		return h, false
	}
	if h.kind != "else" {
		open := strings.IndexByte(code[i:], '(')
		if open < 0 || strings.TrimSpace(code[i:i+open]) != "" {
			return h, false
		}
		open += i
		closing := matchParen(code, open)
		if closing < 0 {
			return h, false
		}
		h.cond = ll.raw[open+1 : closing]
		i = closing + 1
	}
	tail := strings.TrimSpace(code[i:])
	switch {
	case tail == "{" || tail == "":
		h.opens = tail == "{"
	case strings.HasSuffix(tail, "{") && !strings.Contains(tail, ";"):
		h.opens = true
	default:
		h.rest = strings.TrimSpace(ll.raw[i:])
		h.restAt = i + (len(code[i:]) - len(strings.TrimLeft(code[i:], " \t")))
	}
	return h, true
}

// header resolves a control-flow header's state and records a block for it
// when the line opens one. depthBefore is the brace depth at the start of the
// line's own header (after any leading `}`).
func (b *javaBranches) header(h javaHeader, depthHere int) branchState {
	parent := b.state()
	if parent == branchDead {
		if h.opens {
			b.blocks = append(b.blocks, javaBlock{interior: depthHere + 1, state: branchDead})
		}
		return branchDead
	}
	var st branchState
	switch h.kind {
	case "if":
		c := &pyChain{kind: 'i'}
		b.chains[depthHere] = c
		v, ok := b.eval(h.cond)
		st = decideChain(c, v, ok)
	case "elseif":
		c := b.chains[depthHere]
		if c == nil {
			st = branchMaybe
			break
		}
		v, ok := b.eval(h.cond)
		st = decideChain(c, v, ok)
	case "else":
		c := b.chains[depthHere]
		if c == nil {
			st = branchMaybe
			break
		}
		st = decideChain(c, pyValue{kind: 'b', b: true}, true)
	case "loop":
		st = branchMaybe
	case "switch":
		v, ok := b.eval(h.cond)
		if h.opens {
			b.blocks = append(b.blocks, javaBlock{interior: depthHere + 1, state: branchTaken,
				sw: &javaSwitch{subject: v, subjectOK: ok, cur: branchDead}})
		}
		return branchTaken
	}
	if h.opens {
		b.blocks = append(b.blocks, javaBlock{interior: depthHere + 1, state: st})
	}
	return st
}

// decideChain is the if/else-if/else resolution pydead.go uses for Python.
func decideChain(c *pyChain, v pyValue, ok bool) branchState {
	switch {
	case c.decided:
		return branchDead
	case !ok:
		c.unknown = true
		return branchMaybe
	case !v.truthy():
		return branchDead
	case c.unknown:
		return branchMaybe
	default:
		c.decided = true
		return branchTaken
	}
}

// caseLabel handles `case X:` / `default:` in a switch body and returns any
// statement written after the colon on the same line.
func (b *javaBranches) caseLabel(sw *javaSwitch, raw string) string {
	m := javaCaseLabel.FindStringSubmatch(strings.TrimSpace(raw))
	if m == nil {
		return ""
	}
	fallthroughFrom := sw.body && !sw.ended
	label := m[1] // "" for default
	var st branchState
	switch {
	case sw.decided && !fallthroughFrom:
		st = branchDead
	case label == "":
		if sw.unknown {
			st = branchMaybe
		} else {
			st = branchTaken
		}
	case !sw.subjectOK:
		sw.unknown = true
		st = branchMaybe
	default:
		st = branchDead
		for _, alt := range strings.Split(label, ",") {
			v, ok := b.eval(strings.TrimSpace(alt))
			if !ok {
				sw.unknown = true
				st = branchMaybe
				break
			}
			if v.equal(sw.subject) {
				st = branchTaken
				break
			}
		}
		if st == branchTaken && sw.unknown {
			st = branchMaybe
		}
	}
	switch {
	case fallthroughFrom && sw.cur != branchDead:
		// Falling into this case from a live one: it runs whenever that did.
		if st == branchDead {
			st = sw.cur
		}
	case !sw.body && sw.cur != branchDead && len(sw.labels) > 0:
		// Stacked labels (`case 'C': case 'D':`) are alternatives.
		if st == branchDead {
			st = sw.cur
		}
	}
	sw.labels = append(sw.labels, label)
	sw.cur = st
	sw.body, sw.ended = false, false
	return strings.TrimSpace(m[2])
}

// statementInSwitch records that the current case has a body, and whether this
// statement ends it.
func (sw *javaSwitch) statement(trimmed string) {
	sw.body = true
	for _, kw := range []string{"break", "return", "throw", "continue"} {
		if trimmed == kw || strings.HasPrefix(trimmed, kw+" ") || strings.HasPrefix(trimmed, kw+"(") {
			sw.ended = true
			if sw.cur == branchTaken {
				sw.decided = true
			}
		}
	}
}

// learn records a constant a statement binds.
func (b *javaBranches) learn(ll logicalLine, assigns string) {
	if assigns == "" || !b.single[assigns] {
		return
	}
	eq := javaAssignIndex(ll.code)
	if eq < 0 {
		return
	}
	if v, ok := b.eval(pyEvalText(ll, eq+1, len(ll.code))); ok {
		b.env[assigns] = v
	}
}

// javaAssignIndex returns the offset of a statement's plain `=`, or -1.
func javaAssignIndex(code string) int {
	depth := 0
	for i := 0; i < len(code); i++ {
		switch code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '=':
			if depth != 0 || i+1 < len(code) && code[i+1] == '=' {
				if i+1 < len(code) && code[i+1] == '=' {
					i++
				}
				continue
			}
			if i > 0 && strings.ContainsRune("=!<>+-*/%&|^", rune(code[i-1])) {
				continue
			}
			return i
		}
	}
	return -1
}

// rewriteJavaTernary turns `x = C ? a : b` with a constant C into `x = a` or
// `x = b`, blanking the dropped parts in both views.
func (b *javaBranches) rewriteJavaTernary(ll logicalLine) logicalLine {
	code := ll.code
	eq := javaAssignIndex(code)
	if eq < 0 {
		return ll
	}
	q := topLevelKeyword(code[eq:], "?")
	if q < 0 {
		return ll
	}
	q += eq
	colon := topLevelKeyword(code[q:], ":")
	if colon < 0 {
		return ll
	}
	colon += q
	v, ok := b.eval(pyEvalText(ll, eq+1, q))
	if !ok {
		// The condition is unknown, so the value is one of the two arms --
		// but it is never the condition itself: `$x = $x == 'a' ? 'a' : 'b'`
		// assigns a literal whichever way it goes. Blank the condition so its
		// reads do not flow into the assignee. The short form `a ?: b`
		// returns the condition's own value, so it is left alone.
		if q+1 < len(code) && code[q+1] == ':' {
			return ll
		}
		return logicalLine{line: ll.line, code: blankRange(code, eq+1, q+1),
			raw: blankRange(ll.raw, eq+1, min(q+1, len(ll.raw)))}
	}
	end := len(code)
	for end > colon && (code[end-1] == ';' || code[end-1] == ' ') {
		end--
	}
	if v.truthy() {
		return logicalLine{line: ll.line, code: blankRange(blankRange(code, eq+1, q+1), colon, end),
			raw: blankRange(blankRange(ll.raw, eq+1, q+1), colon, min(end, len(ll.raw)))}
	}
	return logicalLine{line: ll.line, code: blankRange(code, eq+1, colon+1),
		raw: blankRange(ll.raw, eq+1, min(colon+1, len(ll.raw)))}
}

// subLine returns the part of a logical line from offset at, as its own line.
func subLine(ll logicalLine, at int) logicalLine {
	if at >= len(ll.code) {
		return logicalLine{line: ll.line}
	}
	return logicalLine{line: ll.line, code: blankRange(ll.code, 0, at), raw: blankRange(ll.raw, 0, min(at, len(ll.raw)))}
}
