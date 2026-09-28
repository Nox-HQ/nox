package engine

import (
	"strconv"
	"strings"
)

// Constant evaluation of Python conditions, for pruning branches that cannot
// run.
//
// `if 7 * 42 - num > 200:` with `num = 106`, `x if 'a' in 'abc' else y`,
// `match "ABC"[1]:` -- a branch whose condition is a constant is either always
// taken or never taken, and treating it as "may run" reports flows through
// code that cannot execute. The OWASP Benchmark for Python builds 63 of its
// false positives this way; real code does it less, but a feature flag held in
// a module constant is the same shape.
//
// The evaluator is deliberately small and refuses rather than guesses: any
// operand it cannot pin to a value -- a call, an attribute, a parameter, a name
// assigned more than once anywhere in the file -- makes the whole expression
// unknown, and an unknown condition leaves the branch exactly as it was. So it
// can only ever remove a branch that provably does not run. The
// "assigned exactly once in the file" rule is what makes that true inside
// loops: a name that changes between iterations is assigned twice and is
// never a constant.

// pyValue is an evaluated constant: an int, a string or a bool.
type pyValue struct {
	kind byte // 'i', 's', 'b'
	i    int64
	s    string
	b    bool
}

func (v pyValue) truthy() bool {
	switch v.kind {
	case 'i':
		return v.i != 0
	case 's':
		return v.s != ""
	}
	return v.b
}

func (v pyValue) equal(o pyValue) bool {
	if v.kind != o.kind {
		return false
	}
	return v.i == o.i && v.s == o.s && v.b == o.b
}

// pyConstEnv maps a name to its constant value.
type pyConstEnv map[string]pyValue

// evalPyConst evaluates a Python expression to a constant, or reports ok=false.
func evalPyConst(expr string, env pyConstEnv) (pyValue, bool) {
	p := &pyConstParser{toks: pyTokens(expr), env: env}
	if p.toks == nil {
		return pyValue{}, false
	}
	v, ok := p.or()
	if !ok || p.pos != len(p.toks) {
		return pyValue{}, false
	}
	return v, true
}

type pyTok struct {
	kind byte // 'n' number, 's' string, 'i' ident/keyword, 'o' operator
	text string
}

// pyTokens splits an expression into tokens, or returns nil on anything the
// evaluator does not model (f-strings, byte strings, floats, escapes).
func pyTokens(s string) []pyTok {
	var out []pyTok
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\\':
			i++
		case c >= '0' && c <= '9':
			j := i
			for j < len(s) && (s[j] >= '0' && s[j] <= '9' || s[j] == '_') {
				j++
			}
			if j < len(s) && (s[j] == '.' || s[j] == 'e' || s[j] == 'x') {
				return nil
			}
			out = append(out, pyTok{'n', strings.ReplaceAll(s[i:j], "_", "")})
			i = j
		case c == '\'' || c == '"':
			j := i + 1
			for j < len(s) && s[j] != c {
				if s[j] == '\\' {
					return nil
				}
				j++
			}
			if j >= len(s) {
				return nil
			}
			out = append(out, pyTok{'s', s[i+1 : j]})
			i = j + 1
		case c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			j := i
			for j < len(s) && isPyIdentByte(s[j]) {
				j++
			}
			if j < len(s) && (s[j] == '\'' || s[j] == '"') {
				return nil // a prefixed string: f'', b'', r''
			}
			out = append(out, pyTok{'i', s[i:j]})
			i = j
		default:
			for _, op := range []string{"//", "==", "!=", "<=", ">=", "**", "+", "-", "*", "%", "<", ">", "(", ")", "[", "]", ":"} {
				if strings.HasPrefix(s[i:], op) {
					out = append(out, pyTok{'o', op})
					i += len(op)
					goto next
				}
			}
			return nil
		next:
		}
	}
	return out
}

func isPyIdentByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

type pyConstParser struct {
	toks []pyTok
	pos  int
	env  pyConstEnv
}

func (p *pyConstParser) peek(kind byte, text string) bool {
	return p.pos < len(p.toks) && p.toks[p.pos].kind == kind && p.toks[p.pos].text == text
}

func (p *pyConstParser) eat(kind byte, text string) bool {
	if p.peek(kind, text) {
		p.pos++
		return true
	}
	return false
}

func (p *pyConstParser) or() (pyValue, bool) {
	v, ok := p.and()
	for ok && p.eat('i', "or") {
		r, rok := p.and()
		if !rok {
			return pyValue{}, false
		}
		v = pyValue{kind: 'b', b: v.truthy() || r.truthy()}
	}
	return v, ok
}

func (p *pyConstParser) and() (pyValue, bool) {
	v, ok := p.not()
	for ok && p.eat('i', "and") {
		r, rok := p.not()
		if !rok {
			return pyValue{}, false
		}
		v = pyValue{kind: 'b', b: v.truthy() && r.truthy()}
	}
	return v, ok
}

func (p *pyConstParser) not() (pyValue, bool) {
	if p.eat('i', "not") {
		v, ok := p.not()
		return pyValue{kind: 'b', b: !v.truthy()}, ok
	}
	return p.comparison()
}

// comparison handles one comparison operator; chained comparisons are refused.
func (p *pyConstParser) comparison() (pyValue, bool) {
	l, ok := p.sum()
	if !ok {
		return pyValue{}, false
	}
	var op string
	switch {
	case p.eat('i', "not"):
		if !p.eat('i', "in") {
			return pyValue{}, false
		}
		op = "not in"
	case p.eat('i', "in"):
		op = "in"
	default:
		for _, o := range []string{"==", "!=", "<=", ">=", "<", ">"} {
			if p.eat('o', o) {
				op = o
				break
			}
		}
	}
	if op == "" {
		return l, true
	}
	r, ok := p.sum()
	if !ok {
		return pyValue{}, false
	}
	switch op {
	case "in", "not in":
		if l.kind != 's' || r.kind != 's' {
			return pyValue{}, false
		}
		in := strings.Contains(r.s, l.s)
		return pyValue{kind: 'b', b: in == (op == "in")}, true
	case "==":
		return pyValue{kind: 'b', b: l.equal(r)}, true
	case "!=":
		return pyValue{kind: 'b', b: !l.equal(r)}, true
	}
	if l.kind != 'i' || r.kind != 'i' {
		return pyValue{}, false
	}
	var b bool
	switch op {
	case "<":
		b = l.i < r.i
	case ">":
		b = l.i > r.i
	case "<=":
		b = l.i <= r.i
	case ">=":
		b = l.i >= r.i
	}
	return pyValue{kind: 'b', b: b}, true
}

func (p *pyConstParser) sum() (pyValue, bool) {
	v, ok := p.product()
	for ok {
		switch {
		case p.eat('o', "+"):
			r, rok := p.product()
			if !rok {
				return pyValue{}, false
			}
			switch {
			case v.kind == 'i' && r.kind == 'i':
				v = pyValue{kind: 'i', i: v.i + r.i}
			case v.kind == 's' && r.kind == 's':
				v = pyValue{kind: 's', s: v.s + r.s}
			default:
				return pyValue{}, false
			}
		case p.eat('o', "-"):
			r, rok := p.product()
			if !rok || v.kind != 'i' || r.kind != 'i' {
				return pyValue{}, false
			}
			v = pyValue{kind: 'i', i: v.i - r.i}
		default:
			return v, true
		}
	}
	return pyValue{}, false
}

func (p *pyConstParser) product() (pyValue, bool) {
	v, ok := p.unary()
	for ok {
		var op string
		for _, o := range []string{"*", "//", "%"} {
			if p.eat('o', o) {
				op = o
				break
			}
		}
		if op == "" {
			return v, true
		}
		r, rok := p.unary()
		if !rok || v.kind != 'i' || r.kind != 'i' {
			return pyValue{}, false
		}
		switch op {
		case "*":
			v = pyValue{kind: 'i', i: v.i * r.i}
		case "//", "%":
			if r.i == 0 || v.i < 0 || r.i < 0 {
				return pyValue{}, false // Python floors; keep to the cases Go agrees on
			}
			if op == "//" {
				v = pyValue{kind: 'i', i: v.i / r.i}
			} else {
				v = pyValue{kind: 'i', i: v.i % r.i}
			}
		}
	}
	return pyValue{}, false
}

func (p *pyConstParser) unary() (pyValue, bool) {
	if p.eat('o', "-") {
		v, ok := p.unary()
		if !ok || v.kind != 'i' {
			return pyValue{}, false
		}
		return pyValue{kind: 'i', i: -v.i}, true
	}
	return p.postfix()
}

// postfix handles indexing a string with an int: `"ABC"[1]`, `possible[0]`.
func (p *pyConstParser) postfix() (pyValue, bool) {
	v, ok := p.atom()
	for ok && p.eat('o', "[") {
		idx, iok := p.sum()
		if !iok || !p.eat('o', "]") || v.kind != 's' || idx.kind != 'i' {
			return pyValue{}, false
		}
		n := int64(len(v.s))
		i := idx.i
		if i < 0 {
			i += n
		}
		if i < 0 || i >= n {
			return pyValue{}, false
		}
		v = pyValue{kind: 's', s: v.s[i : i+1]}
	}
	return v, ok
}

func (p *pyConstParser) atom() (pyValue, bool) {
	if p.pos >= len(p.toks) {
		return pyValue{}, false
	}
	t := p.toks[p.pos]
	p.pos++
	switch t.kind {
	case 'n':
		n, err := strconv.ParseInt(t.text, 10, 64)
		return pyValue{kind: 'i', i: n}, err == nil
	case 's':
		return pyValue{kind: 's', s: t.text}, true
	case 'i':
		switch t.text {
		case "True":
			return pyValue{kind: 'b', b: true}, true
		case "False":
			return pyValue{kind: 'b', b: false}, true
		}
		if p.peek('o', "(") || p.peek('o', ".") {
			return pyValue{}, false // a call
		}
		v, ok := p.env[t.text]
		return v, ok
	case 'o':
		if t.text == "(" {
			v, ok := p.or()
			if !ok || !p.eat('o', ")") {
				return pyValue{}, false
			}
			return v, true
		}
	}
	return pyValue{}, false
}
