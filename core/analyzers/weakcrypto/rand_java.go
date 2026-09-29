// Insecure randomness in Java — CRYPTO-002, third language.
//
// The premise is the Go and Python one (rand.go, rand_python.go): a draw from a
// predictable generator is reported only where the surrounding names say the
// value is a secret, and a benign name vetoes it. Java differs in which calls
// draw and in how a statement is found; the naming evidence -- assignment
// target, the calls the value is passed to, the enclosing method, and one
// forward hop through a neutral local -- is gathered by the same contextAt the
// Python scanner uses.
//
// WHICH GENERATOR. java.util.Random, Math.random, ThreadLocalRandom and
// commons-lang's static RandomStringUtils.random* are predictable (a
// java.util.Random seed is recoverable from two outputs). SecureRandom is the
// fix and never fires. SecureRandom extends Random, so a local counts as a
// predictable generator by the constructor it was made with, never by its
// declared type: `Random r = new SecureRandom()` is secure.
//
// Measured before shipping, as the other two languages were: the OWASP
// Benchmark for Java stores `new java.util.Random().nextLong()` into a local,
// converts it into `rememberMeKey`, and writes that into the session. The
// forward hop through the neutral local is what finds it.
//
// KNOWN FALSE NEGATIVES. A generator passed in as a field or parameter, a value
// that reaches a secret through a helper method, and a security use more than
// one assignment away.

package weakcrypto

import (
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
)

var (
	javaDrawMethods = `next(?:Int|Long|Double|Float|Boolean|Bytes|Gaussian)|ints|longs|doubles`
	javaNewRandom   = regexp.MustCompile(`\bnew\s+(?:java\s*\.\s*util\s*\.\s*)?Random\s*\([^()]*\)\s*\.\s*(` + javaDrawMethods + `)\s*\(`)
	javaMathRandom  = regexp.MustCompile(`\b(?:java\s*\.\s*lang\s*\.\s*)?Math\s*\.\s*(random)\s*\(`)
	javaThreadLocal = regexp.MustCompile(`\bThreadLocalRandom\s*\.\s*current\s*\(\s*\)\s*\.\s*(` + javaDrawMethods + `)\s*\(`)
	javaRandomUtils = regexp.MustCompile(`\bRandomStringUtils\s*\.\s*(random\w*)\s*\(`)
	javaRngDecl     = regexp.MustCompile(`\b([A-Za-z_]\w*)\s*=\s*new\s+(?:java\s*\.\s*util\s*\.\s*)?Random\s*\(`)
	javaOtherRandom = regexp.MustCompile(`(?m)^\s*import\s+(?:static\s+)?([\w.]+)\.Random\s*;`)
	javaMethodHead  = regexp.MustCompile(`([A-Za-z_]\w*)\s*\([^;]*\)\s*(?:throws\s+[\w.,\s]+)?$`)
	javaIndexBound  = regexp.MustCompile(`\.\s*(?:size\s*\(\s*\)|length\b)`)
)

// javaControlWords head a block without being a method.
var javaControlWords = map[string]bool{
	"if": true, "for": true, "while": true, "switch": true, "catch": true,
	"synchronized": true, "try": true, "else": true, "do": true, "return": true,
}

// javaStmt is one statement (text up to `;`) or block header (text up to `{`).
type javaStmt struct {
	start, end int
	depth      int // brace depth the statement sits at
	header     bool
}

// javaStatements splits masked Java into statements and block headers.
// Semicolons inside parentheses (a for header) do not end a statement.
func javaStatements(masked []byte) []javaStmt {
	var out []javaStmt
	depth, paren, start := 0, 0, 0
	emit := func(end int, header bool) {
		if strings.TrimSpace(string(masked[start:end])) != "" {
			out = append(out, javaStmt{start: start, end: end, depth: depth, header: header})
		}
		start = end + 1
	}
	for i := 0; i < len(masked); i++ {
		switch masked[i] {
		case '(':
			paren++
		case ')':
			if paren > 0 {
				paren--
			}
		case ';':
			if paren == 0 {
				emit(i, false)
			}
		case '{':
			if paren == 0 {
				emit(i, true)
				depth++
			}
		case '}':
			if paren == 0 {
				emit(i, false)
				if depth > 0 {
					depth--
				}
			}
		}
	}
	return out
}

// scanInsecureRandomJava reports predictable draws named for a security use in
// one Java file.
func scanInsecureRandomJava(fs *findings.FindingSet, art discovery.Artifact, content []byte) {
	if !strings.Contains(string(content), "andom") {
		return
	}
	masked := lexctx.MaskNonCode(lexctx.LangJava, content)
	// A bare `Random` that some other package's import supplies is not
	// java.util.Random.
	bareRandomOK := true
	for _, m := range javaOtherRandom.FindAllSubmatch(masked, -1) {
		if strings.ReplaceAll(string(m[1]), " ", "") != "java.util" {
			bareRandomOK = false
		}
	}
	var rngVars []string
	for _, m := range javaRngDecl.FindAllSubmatch(masked, -1) {
		rngVars = append(rngVars, string(m[1]))
	}
	var rngCall *regexp.Regexp
	if len(rngVars) > 0 {
		rngCall = regexp.MustCompile(`(?:^|[^\w.])(` + strings.Join(rngVars, "|") + `)\s*\.\s*(` + javaDrawMethods + `)\s*\(`)
	}
	stmts := javaStatements(masked)
	reported := map[int]bool{}
	for si, st := range stmts {
		if st.header {
			continue
		}
		text := string(masked[st.start:st.end])
		type draw struct {
			at int
			fn string
		}
		var draws []draw
		for _, re := range []*regexp.Regexp{javaNewRandom, javaMathRandom, javaThreadLocal, javaRandomUtils} {
			if re == javaNewRandom && !bareRandomOK && !strings.Contains(text, "java") {
				continue
			}
			for _, m := range re.FindAllStringSubmatchIndex(text, -1) {
				draws = append(draws, draw{at: m[0], fn: text[m[2]:m[3]]})
			}
		}
		if rngCall != nil {
			for _, m := range rngCall.FindAllStringSubmatchIndex(text, -1) {
				draws = append(draws, draw{at: m[2], fn: text[m[4]:m[5]]})
			}
		}
		for _, d := range draws {
			at := st.start + d.at
			for at < st.end && masked[at] == ' ' {
				at++
			}
			line := lexctx.LineForOffset(content, at)
			if reported[line] {
				continue
			}
			names, _, target := contextAt(content, masked, st.start, at)
			if target == "" {
				target = javaDeclaredName(text[:d.at])
			}
			args := javaCallArgs(masked, at, st.end)
			if d.fn == "nextBytes" {
				// Like Go's Read: the buffer argument is what becomes random.
				if buf := trailingPyName(strings.TrimSpace(args)); buf != "" {
					names = append(names, ctxName{name: unglue(buf), role: roleValue})
					target = buf
				}
			}
			if target != "" {
				names = append(names, javaForwardUses(content, masked, stmts, si, target)...)
			}
			if fn := javaEnclosingMethod(masked, stmts, si); fn != "" {
				names = append(names, ctxName{name: funcContext(fn), role: roleFunc})
			}
			indexDraw := strings.HasPrefix(d.fn, "nextInt") && javaIndexBound.MatchString(args) ||
				isIndexName(target)
			hit, vetoed := classify(names, indexDraw)
			if vetoed || hit == "" {
				continue
			}
			reported[line] = true
			fs.Add(findings.Finding{
				RuleID:     randRuleID,
				Severity:   findings.SeverityHigh,
				Confidence: findings.ConfidenceMedium,
				Message: "Predictable randomness: " + d.fn +
					" produces a value named for a security use (" + hit + "); use java.security.SecureRandom",
				Location: findings.Location{FilePath: art.Path, StartLine: line, EndLine: line},
				Metadata: map[string]string{
					"cwe":      "CWE-338",
					"function": d.fn,
					"context":  hit,
					"language": "java",
				},
			})
		}
	}
}

// javaDeclaredName returns the local a statement declares or assigns --
// `rand` in `float rand = …` and `final String key = …` -- or "" for anything
// but a plain `[modifiers] [Type] name =` head.
func javaDeclaredName(head string) string {
	eq := topLevelAssign(head)
	if eq < 0 {
		return ""
	}
	fields := strings.Fields(head[:eq])
	if len(fields) == 0 {
		return ""
	}
	name := fields[len(fields)-1]
	if !pyIdentRe.MatchString(name) {
		return ""
	}
	return name
}

// javaCallArgs returns the argument text of the last call in the chain that
// starts at `at` -- the draw's own arguments in `new Random(seed).nextInt(n)`.
func javaCallArgs(masked []byte, at, end int) string {
	args := ""
	for i := at; i < end; {
		open := strings.IndexByte(string(masked[i:end]), '(')
		if open < 0 {
			break
		}
		open += i
		closing := pyCloseOf(masked, open)
		if closing >= end || closing <= open {
			break
		}
		args = string(masked[open+1 : closing])
		rest := strings.TrimLeft(string(masked[closing+1:end]), " \t\n")
		if !strings.HasPrefix(rest, ".") {
			break
		}
		i = closing + 1
	}
	return args
}

// javaForwardUses gathers the context of each later use of `name` in the same
// block, up to its next reassignment -- the Java counterpart of pyForwardUses.
func javaForwardUses(content, masked []byte, stmts []javaStmt, from int, name string) []ctxName {
	useRe := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`)
	depth := stmts[from].depth
	var out []ctxName
	for si := from + 1; si < len(stmts); si++ {
		st := stmts[si]
		if st.depth < depth {
			break
		}
		text := string(masked[st.start:st.end])
		if eq := topLevelAssign(text); eq >= 0 && trailingPyName(text[:eq]) == name && !st.header {
			if strings.TrimSpace(strings.TrimRight(text[:eq], "+-*/%&|^<> \t")) == name {
				break
			}
		}
		for _, loc := range useRe.FindAllStringIndex(text, -1) {
			if loc[0] > 0 && text[loc[0]-1] == '.' {
				continue
			}
			names, enclosing, _ := contextAt(content, masked, st.start, st.start+loc[0])
			if anyLookup(enclosing) {
				continue
			}
			out = append(out, names...)
		}
	}
	return out
}

// javaEnclosingMethod returns the name of the method whose body holds
// statement si, or "".
func javaEnclosingMethod(masked []byte, stmts []javaStmt, si int) string {
	depth := stmts[si].depth
	for i := si - 1; i >= 0; i-- {
		st := stmts[i]
		if !st.header || st.depth >= depth {
			continue
		}
		depth = st.depth
		m := javaMethodHead.FindStringSubmatch(strings.TrimSpace(string(masked[st.start:st.end])))
		if len(m) == 2 && !javaControlWords[m[1]] {
			return m[1]
		}
	}
	return ""
}
