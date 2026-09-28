// Insecure randomness in Python — CRYPTO-002, second language.
//
// The rule is the Go one (rand.go): a draw from a predictable generator is
// reported only where the surrounding names say the value is security-bearing,
// and a benign name vetoes it. What differs is how the names are found, and
// three decisions that Python forces:
//
// WHICH GENERATOR. `random`'s module functions and `random.Random` instances
// are a Mersenne Twister, recoverable from 624 observed 32-bit outputs.
// `random.SystemRandom` and the `secrets` module read the OS CSPRNG and are the
// fix, so they never fire. `random.SystemRandom().randint(…)` is excluded by
// shape: the receiver of `.randint` is a call, not the module.
//
// FINDING THE NAMES WITHOUT A PARSER. The file is masked by
// lexctx.MaskNonCode (string bodies and comments blanked, offsets kept, an
// f-string's interpolations left as code) and split into logical lines, so a call
// spread over several lines is still one statement. For a call the context is:
// the assignment target, a keyword-argument or dict-key name, the functions it
// is passed to, and the enclosing `def`. Then ONE forward hop: if the value is
// bound to a plain name, that name's later uses in the same function add their
// own context, because the common shape is
//
//	value = str(random.getrandbits(32))
//	session[cookie] = value
//
// where the first line says nothing and the second says everything. One hop,
// it stops at a reassignment, and a use as a getter's argument is skipped: in
// `csrf = get_csrf_token(value)` the value selects, it does not become.
//
// THE ENCLOSING FUNCTION'S NAME. In Go, any benign word in any context name
// vetoes. For Python the function name vetoes only on a PURPOSE word (retry,
// backoff, sample, …) or when it is a pytest test (`test_…`). Code-kind words —
// demo, example, fake, bench — elsewhere in a function name say where the code
// sits, not what the value is for, and test code is already excluded by path.
// Measured on the OWASP Benchmark for Python, whose handlers are all named
// `BenchmarkTestNNNNN_post`: under the Go veto every case, vulnerable or not,
// is silent, which is the rule reporting on its own naming heuristic rather
// than on the code.
//
// GLUED WORDS. Python names are often lowercase without separators:
// `mysession`, `authtoken`. A word that ENDS in a long security word is split
// before classifying. Long ones only — `session`, `secret`, `token`,
// `password`, `credential`, `apikey`, `nonce` — so `monkey` and `hotkey` stay
// single words and silent.
//
// KNOWN FALSE NEGATIVES. numpy.random, a generator passed in as a parameter, a
// value laundered through a helper, and a security use more than one
// assignment away are not seen.

package weakcrypto

import (
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
)

// pyWeakFns are the `random` functions that draw a value. `seed`, `getstate`
// and `setstate` configure the generator and are not draws.
var pyWeakFns = map[string]bool{
	"random": true, "randint": true, "randrange": true, "getrandbits": true,
	"randbytes": true, "choice": true, "choices": true, "sample": true,
	"shuffle": true, "uniform": true, "triangular": true, "gauss": true,
	"normalvariate": true, "lognormvariate": true, "expovariate": true,
	"vonmisesvariate": true, "gammavariate": true, "betavariate": true,
	"paretovariate": true, "weibullvariate": true, "binomialvariate": true,
}

// pyPickFns choose an element rather than make a value; see pyIndexDraw.
var pyPickFns = map[string]bool{"choice": true, "sample": true, "shuffle": true}

// codeKindWords say what kind of code a function is, not what a value is for.
// See THE ENCLOSING FUNCTION'S NAME above.
var codeKindWords = map[string]bool{
	"test": true, "testing": true, "fake": true, "mock": true, "dummy": true,
	"stub": true, "fixture": true, "example": true, "demo": true,
	"bench": true, "benchmark": true,
}

// gluedSecuritySuffixes are split off the end of a lowercase word; see GLUED
// WORDS above.
var gluedSecuritySuffixes = []string{
	"session", "secret", "token", "password", "credential", "apikey", "nonce",
}

var (
	pyImportRe     = regexp.MustCompile(`^\s*import\s+(.+)$`)
	pyFromImportRe = regexp.MustCompile(`^\s*from\s+random\s+import\s+\(?([^)]*)\)?`)
	pyCallRe       = regexp.MustCompile(`[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*\s*\(`)
	pyDefRe        = regexp.MustCompile(`^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)`)
	pyKwargRe      = regexp.MustCompile(`^\s*([A-Za-z_]\w*)\s*=(?:[^=]|$)`)
	pyDictKeyRe    = regexp.MustCompile(`^\s*[rbuRBU]?(["'])(\w+)["']\s*:`)
	pyStringKeyRe  = regexp.MustCompile(`\[\s*[rbuRBU]?["'](\w+)["']\s*\]`)
	pyIdentRe      = regexp.MustCompile(`^[A-Za-z_]\w*$`)
	pyLenCallRe    = regexp.MustCompile(`(?:^|[^\w.])len\s*\(`)
)

// pyRandBindings is what a file binds to the predictable generator.
type pyRandBindings struct {
	modules map[string]bool   // `random`, or its alias
	funcs   map[string]string // local name -> random function, from `from random import`
	rngs    map[string]bool   // names assigned a random.Random(...) instance
	ctors   map[string]bool   // local names for random.Random itself
}

func (b pyRandBindings) empty() bool {
	return len(b.modules) == 0 && len(b.funcs) == 0 && len(b.ctors) == 0
}

// pyLine is one logical line: a statement, however many physical lines it spans.
type pyLine struct {
	start, end int // byte offsets in the file
	line       int // 1-based physical line of start
	indent     int
}

// scanInsecureRandomPython reports predictable `random` draws that the
// surrounding names identify as security-bearing, in one Python file.
func scanInsecureRandomPython(fs *findings.FindingSet, art discovery.Artifact, content []byte) {
	masked := lexctx.MaskNonCode(lexctx.LangPython, content)
	lines := pyLogicalLines(masked)
	b := pyBindings(masked, lines)
	if b.empty() {
		return
	}
	reported := map[int]bool{}
	for li, ln := range lines {
		text := string(masked[ln.start:ln.end])
		for _, loc := range pyCallRe.FindAllStringIndex(text, -1) {
			at := ln.start + loc[0]
			if at > 0 && (isPyWordByte(masked[at-1]) || masked[at-1] == '.') {
				continue // part of a longer chain: `x.random.randint` or `SystemRandom().randint`
			}
			fn, ok := b.weakCall(text[loc[0]:loc[1]])
			if !ok {
				continue
			}
			line := ln.line + strings.Count(string(content[ln.start:at]), "\n")
			if reported[line] {
				continue
			}
			names, enclosing, target := pyContextAt(content, masked, ln.start, at)
			if target != "" {
				names = append(names, pyForwardUses(content, masked, lines, li, target)...)
			}
			if fn := pyEnclosingFunc(masked, lines, li); fn != "" {
				names = append(names, ctxName{name: pyFuncContext(fn), role: roleFunc})
			}
			args := string(masked[ln.start+loc[1] : pyCloseOf(masked, ln.start+loc[1]-1)])
			hit, vetoed := classify(names, pyIndexDraw(fn, enclosing, args))
			if vetoed || hit == "" {
				continue
			}
			reported[line] = true
			fs.Add(findings.Finding{
				RuleID:     randRuleID,
				Severity:   findings.SeverityHigh,
				Confidence: findings.ConfidenceMedium,
				Message: "Predictable randomness: random." + fn +
					" produces a value named for a security use (" + hit + "); use the secrets module",
				Location: findings.Location{FilePath: art.Path, StartLine: line, EndLine: line},
				Metadata: map[string]string{
					"cwe":      "CWE-338",
					"function": "random." + fn,
					"context":  hit,
				},
			})
		}
	}
}

// weakCall reports whether a call head (`random.randint(`, `rng.random(`,
// `randint(`) draws from the predictable generator, and names the function.
func (b pyRandBindings) weakCall(head string) (string, bool) {
	chain := strings.Fields(strings.NewReplacer(".", " ", "(", " ").Replace(head))
	switch len(chain) {
	case 1:
		fn, ok := b.funcs[chain[0]]
		return fn, ok
	case 0:
		return "", false
	}
	fn := chain[len(chain)-1]
	if !pyWeakFns[fn] {
		return "", false
	}
	recv := chain[len(chain)-2]
	if len(chain) == 2 && b.modules[recv] || b.rngs[recv] {
		return fn, true
	}
	return "", false
}

// pyBindings collects the module aliases, from-imported functions and Random
// instances a file binds.
func pyBindings(masked []byte, lines []pyLine) pyRandBindings {
	b := pyRandBindings{modules: map[string]bool{}, funcs: map[string]string{},
		rngs: map[string]bool{}, ctors: map[string]bool{}}
	for _, ln := range lines {
		text := strings.Join(strings.Fields(string(masked[ln.start:ln.end])), " ")
		if m := pyFromImportRe.FindStringSubmatch(text); m != nil {
			for _, item := range strings.Split(m[1], ",") {
				name, local := pyImportItem(item)
				switch {
				case pyWeakFns[name]:
					b.funcs[local] = name
				case name == "Random":
					b.ctors[local] = true
				}
			}
			continue
		}
		if m := pyImportRe.FindStringSubmatch(text); m != nil && !strings.HasPrefix(strings.TrimSpace(text), "from") {
			for _, item := range strings.Split(m[1], ",") {
				if name, local := pyImportItem(item); name == "random" {
					b.modules[local] = true
				}
			}
		}
	}
	if len(b.modules) == 0 && len(b.ctors) == 0 {
		return b
	}
	// `rng = random.Random(seed)` / `self.rng = Random()`: calls on it draw too.
	for _, ln := range lines {
		text := string(masked[ln.start:ln.end])
		eq := topLevelAssign(text)
		if eq < 0 {
			continue
		}
		rhs := strings.Join(strings.Fields(text[eq+1:]), "")
		isRandom := b.ctors[strings.SplitN(rhs, "(", 2)[0]] && strings.Contains(rhs, "(")
		for m := range b.modules {
			if strings.HasPrefix(rhs, m+".Random(") {
				isRandom = true
			}
		}
		if !isRandom {
			continue
		}
		for _, t := range strings.Split(text[:eq], ",") {
			if n := trailingPyName(t); n != "" {
				b.rngs[n] = true
			}
		}
	}
	return b
}

// pyImportItem splits `name as local` into its parts.
func pyImportItem(item string) (name, local string) {
	f := strings.Fields(item)
	switch {
	case len(f) == 3 && f[1] == "as":
		return f[0], f[2]
	case len(f) == 1:
		return f[0], f[0]
	}
	return "", ""
}

// pyContextAt walks outward from a call at `at` to the start of its statement,
// collecting the names that describe the value: each enclosing call, a keyword
// argument or dict key it is bound to, and the assignment target. It also
// returns the enclosing call names (for pyIndexDraw) and, when the value is
// assigned to one plain name, that name (for the forward hop).
func pyContextAt(content, masked []byte, lineStart, at int) (names []ctxName, enclosing []string, target string) {
	add := func(n string, r role) {
		if n != "" {
			names = append(names, ctxName{name: pyUnglue(n), role: r})
		}
	}
	child, segStart, depth := at, -1, 0
	for i := at - 1; i >= lineStart; i-- {
		switch masked[i] {
		case ')', ']', '}':
			depth++
		case ',':
			if depth == 0 && segStart < 0 {
				segStart = i + 1
			}
		case '(', '[', '{':
			if depth > 0 {
				depth--
				continue
			}
			from := i + 1
			if segStart >= 0 {
				from = segStart
			}
			seg := string(masked[from:child])
			if m := pyKwargRe.FindStringSubmatch(seg); m != nil {
				add(m[1], roleValue)
			}
			if m := pyDictKeyRe.FindStringSubmatch(string(content[from:child])); m != nil && masked[i] == '{' {
				add(m[2], roleValue)
			}
			child, segStart = i, -1
			if masked[i] != '(' {
				continue
			}
			name := trailingPyName(string(masked[lineStart:i]))
			if name == "" {
				continue
			}
			child = i - len(name)
			for child > lineStart && masked[child-1] == ' ' {
				child--
			}
			enclosing = append(enclosing, name)
			r := roleValue
			if isLookup(name) {
				r = roleVetoOnly
			}
			add(name, r)
			// String literals in the same call describe the value, as in Go:
			// veto-only, far too weak to accuse on.
			for _, lit := range pyStringLiterals(content, masked, i, pyCloseOf(masked, i)) {
				add(lit, roleVetoOnly)
			}
		}
	}
	stmt := string(masked[lineStart:child])
	eq := topLevelAssign(stmt)
	if eq < 0 {
		return names, enclosing, ""
	}
	lhs := strings.TrimRight(stmt[:eq], "+-*/%&|^@<> \t") // augmented: `key += …`
	if c := strings.Index(lhs, ":"); c >= 0 && !strings.Contains(lhs, "[") {
		lhs = lhs[:c] // annotated assignment: `token: str = …`
	}
	targets := strings.Split(lhs, ",")
	for _, t := range targets {
		add(trailingPyName(t), roleValue)
	}
	for _, m := range pyStringKeyRe.FindAllStringSubmatch(string(content[lineStart:lineStart+len(lhs)]), -1) {
		add(m[1], roleValue)
	}
	if len(targets) == 1 {
		if t := strings.TrimSpace(targets[0]); pyIdentRe.MatchString(t) {
			target = t
		}
	}
	return names, enclosing, target
}

// pyForwardUses gathers the context of each later use of `name` in the same
// function, up to its next reassignment. See FINDING THE NAMES above.
func pyForwardUses(content, masked []byte, lines []pyLine, from int, name string) []ctxName {
	def := pyEnclosingDef(masked, lines, from)
	if def < 0 {
		return nil // module level: no bounded scope to follow the name through
	}
	useRe := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`)
	var out []ctxName
	for li := from + 1; li < len(lines); li++ {
		ln := lines[li]
		if ln.indent <= lines[def].indent {
			break
		}
		text := string(masked[ln.start:ln.end])
		if eq := topLevelAssign(text); eq >= 0 && strings.TrimSpace(text[:eq]) == name {
			break
		}
		for _, loc := range useRe.FindAllStringIndex(text, -1) {
			if loc[0] > 0 && text[loc[0]-1] == '.' {
				continue
			}
			names, enclosing, _ := pyContextAt(content, masked, ln.start, ln.start+loc[0])
			if anyLookup(enclosing) {
				// `csrf = get_csrf_token(value)`: the value selects what the
				// call returns; the result's name says nothing about the value.
				continue
			}
			out = append(out, names...)
		}
	}
	return out
}

func anyLookup(calls []string) bool {
	for _, c := range calls {
		if isLookup(c) {
			return true
		}
	}
	return false
}

// pyEnclosingDef returns the index of the logical line holding the `def` that
// encloses line li, or -1 at module level.
func pyEnclosingDef(masked []byte, lines []pyLine, li int) int {
	indent := lines[li].indent
	for i := li - 1; i >= 0; i-- {
		if lines[i].indent >= indent {
			continue
		}
		if pyDefRe.Match(masked[lines[i].start:lines[i].end]) {
			return i
		}
		indent = lines[i].indent
	}
	return -1
}

func pyEnclosingFunc(masked []byte, lines []pyLine, li int) string {
	d := pyEnclosingDef(masked, lines, li)
	if d < 0 {
		return ""
	}
	return string(pyDefRe.FindSubmatch(masked[lines[d].start:lines[d].end])[1])
}

// pyFuncContext is the enclosing function's name as it may take part in
// classify: code-kind words are dropped unless the name opens with `test`, the
// pytest convention. See THE ENCLOSING FUNCTION'S NAME above.
func pyFuncContext(fn string) string {
	words := identWords(fn)
	if len(words) > 0 && words[0] == "test" {
		return fn
	}
	kept := words[:0:0]
	for _, w := range words {
		if !codeKindWords[w] {
			kept = append(kept, w)
		}
	}
	return pyUnglue(strings.Join(kept, "_"))
}

// pyIndexDraw reports a draw that chooses rather than makes: `random.choice`,
// `sample` or `shuffle` outside a `join` (where the choices BECOME a string,
// the classic weak token generator), or a randint/randrange whose arguments
// are bounded by len().
func pyIndexDraw(fn string, enclosing []string, args string) bool {
	if pyPickFns[fn] {
		for _, e := range enclosing {
			if e == "join" {
				return false
			}
		}
		return true
	}
	return (fn == "randint" || fn == "randrange") && pyLenCallRe.MatchString(args)
}

// pyUnglue splits a security word glued onto the end of a lowercase word.
func pyUnglue(name string) string {
	words := identWords(name)
	for i, w := range words {
		for _, s := range gluedSecuritySuffixes {
			if len(w) > len(s) && strings.HasSuffix(w, s) && !securityWords[w] {
				words[i] = w[:len(w)-len(s)] + "_" + s
				break
			}
		}
	}
	if len(words) == 0 {
		return name
	}
	return strings.Join(words, "_")
}

// topLevelAssign returns the offset of a statement's assignment `=` (plain or
// augmented) outside brackets, or -1. Comparisons and keyword arguments are not
// assignments.
func topLevelAssign(s string) int {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '=':
			if depth != 0 {
				continue
			}
			if i+1 < len(s) && s[i+1] == '=' {
				i++
				continue
			}
			if i > 0 && strings.ContainsRune("=!<>", rune(s[i-1])) {
				continue
			}
			return i
		}
	}
	return -1
}

// trailingPyName returns the last identifier of an expression's tail —
// `token` for `self.token`, `session` for `session[k]` — or "".
func trailingPyName(s string) string {
	s = strings.TrimRight(s, " \t")
	if strings.HasSuffix(s, "]") { // `x[...]`: name the container
		depth := 0
		for i := len(s) - 1; i >= 0; i-- {
			switch s[i] {
			case ']':
				depth++
			case '[':
				depth--
				if depth == 0 {
					return trailingPyName(s[:i])
				}
			}
		}
		return ""
	}
	end := len(s)
	start := end
	for start > 0 && isPyWordByte(s[start-1]) {
		start--
	}
	if start == end || s[start] >= '0' && s[start] <= '9' {
		return ""
	}
	return s[start:end]
}

func isPyWordByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// pyCloseOf returns the offset of the bracket closing the one at open, or the
// end of the masked text.
func pyCloseOf(masked []byte, open int) int {
	depth := 0
	for i := open; i < len(masked); i++ {
		switch masked[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return len(masked)
}

// pyStringLiterals returns the bodies of the string literals in [from, to).
// The mask keeps quotes and blanks bodies, so a literal is a quoted run whose
// masked body is all blank.
func pyStringLiterals(content, masked []byte, from, to int) []string {
	var out []string
	for i := from; i < to; i++ {
		q := masked[i]
		if q != '"' && q != '\'' {
			continue
		}
		j := i + 1
		for j < to && masked[j] != q {
			j++
		}
		if j >= to {
			break
		}
		if body := strings.TrimSpace(string(content[i+1 : j])); body != "" {
			out = append(out, body)
		}
		i = j
	}
	return out
}

// pyLogicalLines splits a file into statements: physical lines joined while a
// bracket is open or the line ends in a backslash. Blank lines are dropped.
func pyLogicalLines(masked []byte) []pyLine {
	var out []pyLine
	start, line, depth := 0, 1, 0
	startLine := 1
	flush := func(end int) {
		text := masked[start:end]
		if strings.TrimSpace(string(text)) != "" {
			indent := 0
			for indent < len(text) && (text[indent] == ' ' || text[indent] == '\t') {
				indent++
			}
			out = append(out, pyLine{start: start, end: end, line: startLine, indent: indent})
		}
	}
	for i := 0; i < len(masked); i++ {
		switch masked[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case '\n':
			line++
			continued := i > 0 && masked[i-1] == '\\'
			if depth == 0 && !continued {
				flush(i)
				start, startLine = i+1, line
			}
		}
	}
	flush(len(masked))
	return out
}
