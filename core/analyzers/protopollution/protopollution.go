// Package protopollution detects JavaScript and TypeScript deep-merge helpers
// that can pollute Object.prototype (CWE-1321).
//
// WHY THIS IS ITS OWN ANALYZER. Prototype pollution is a property of a
// function's shape, not of a flow: a recursive merge that walks every key of
// its input and recurses into target[key] reaches Object.prototype as soon as
// one key is "__proto__" (or "constructor" then "prototype"), wherever the
// input came from. JSON.parse creates "__proto__" as an ordinary own key, so a
// request body carries one with no effort. A taint rule would need the merge's
// input traced to the request; the helper is the defect, and it is reported
// where it is written, at the recursive call.
//
// WHAT IS REPORTED. A function that loops over the keys of an object (for-in,
// for-of over Object.keys/entries, Object.keys(...).forEach) and calls itself
// with target[key] as an argument, or assigns its own recursion to
// target[key] -- with no __proto__/constructor/prototype check anywhere in its
// body.
//
// WHAT IS NOT. A shallow copy (target[key] = source[key] without recursion):
// assigning target.__proto__ changes that one object's prototype, not the
// global one. A recursion not indexed by the loop key. A body that names
// "__proto__", "constructor" or "prototype" as a string, or tests the key
// against a set or predicate named for unsafe or forbidden keys: that is the
// fix, and code that applies it is not reported. hasOwnProperty is NOT a
// guard -- a parsed "__proto__" key is an own property.
package protopollution

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/rules"
	"github.com/nox-hq/nox/core/source"
)

// Analyzer reports unguarded recursive merges in JavaScript and TypeScript.
type Analyzer struct{}

// NewAnalyzer constructs the prototype-pollution analyzer.
func NewAnalyzer() *Analyzer { return &Analyzer{} }

const ruleID = "PROTO-001"

// Rules returns the rule this analyzer can emit, for the rule catalogue.
func (a *Analyzer) Rules() *rules.RuleSet {
	rs := rules.NewRuleSet()
	rs.Add(&rules.Rule{
		ID:          ruleID,
		Version:     "1.0",
		Description: "Recursive merge without a __proto__/constructor guard: prototype pollution (CWE-1321)",
		Severity:    findings.SeverityMedium,
		// Medium: the shape is established syntactically and the guards are
		// recognised, but whether untrusted input reaches the helper depends
		// on callers this analyzer does not see.
		Confidence: findings.ConfidenceMedium,
		Tags:       []string{"javascript", "typescript", "prototype-pollution", "cwe-1321"},
		Remediation: "This function merges an object into another recursively, key by key, and never refuses the keys that reach the prototype. " +
			"Given input such as JSON.parse('{\"__proto__\": {\"isAdmin\": true}}'), the recursion walks into target.__proto__ -- Object.prototype -- and every object in the process gains isAdmin. " +
			"Skip the dangerous keys before recursing (`if (key === \"__proto__\" || key === \"constructor\" || key === \"prototype\") continue;`), " +
			"or build the result on Object.create(null), or use a maintained merge that already refuses them.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/1321.html",
			"https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf",
		},
		Metadata: map[string]string{"cwe": "CWE-1321"},
	})
	return rs
}

var jsExts = map[string]bool{".js": true, ".mjs": true, ".cjs": true, ".jsx": true, ".ts": true, ".mts": true, ".cts": true, ".tsx": true}

// ScanArtifacts reports unguarded recursive merges across JS/TS sources.
func (a *Analyzer) ScanArtifacts(ctx context.Context, artifacts []discovery.Artifact) (*findings.FindingSet, error) {
	fs := findings.NewFindingSet()
	for _, art := range artifacts {
		if err := ctx.Err(); err != nil {
			return fs, err
		}
		if !jsExts[strings.ToLower(filepath.Ext(art.Path))] || strings.HasSuffix(art.Path, ".d.ts") || source.IsTestPath(art.Path) {
			continue
		}
		content, err := os.ReadFile(art.AbsPath)
		if err != nil || source.IsGenerated(content) {
			continue
		}
		for _, f := range scanFile(art.Path, content) {
			fs.Add(f)
		}
	}
	return fs, nil
}

var (
	// A named definition: NAME(params) [: type] {  -- a function declaration
	// or a method. A call is never followed by a block.
	namedDef = regexp.MustCompile(`([A-Za-z_$][\w$]*)\s*(?:<[^<>()]*>)?\s*\(`)
	// A function bound to a name: NAME = [async] (params) [: type] => {,
	// NAME = function (params) {, NAME: function (params) {.
	boundDef = regexp.MustCompile(`([A-Za-z_$][\w$]*)\s*(?::[^=;{}()]*)?[=:]\s*(?:async\s*)?(?:function\b\s*\*?\s*[\w$]*\s*)?\(`)

	// Loops over an object's keys: the key variable, and the iterated
	// expression (the source of the keys).
	keyLoops = []*regexp.Regexp{
		regexp.MustCompile(`for\s*\(\s*(?:const|let|var)\s+(?P<key>[\w$]+)\s+(?:in|of)\s+(?P<src>[^)]*)\)`),
		regexp.MustCompile(`for\s*\(\s*(?:const|let|var)\s+\[\s*(?P<key>[\w$]+)\s*,[^\]]*\]\s+of\s+(?P<src>[^)]*)\)`),
		regexp.MustCompile(`(?:Object\.(?:keys|entries|getOwnPropertyNames)|Reflect\.ownKeys)\((?P<src>[^)]*)\)\s*\.forEach\(\s*(?:async\s*)?\(?\s*\[?\s*(?P<key>[\w$]+)`),
	}
	lastIdent = regexp.MustCompile(`[A-Za-z_$][\w$]*`)

	// A guard written as a string: the keys themselves.
	guardLiteral = regexp.MustCompile("__proto__|['\"`](?:constructor|prototype)['\"`]")
	// A guard written as a name: a set or predicate for the unsafe keys.
	guardName = regexp.MustCompile(`(?i)\b[\w$]*(?:unsafe|forbidden|blocked|dangerous|reserved|denylist|blacklist|disallowed|pollut)[\w$]*\b|\bis[\w$]*(?:safe|proto)[\w$]*\s*\(`)
)

var keywords = map[string]bool{
	"if": true, "for": true, "while": true, "switch": true, "catch": true, "with": true,
	"function": true, "return": true, "typeof": true, "new": true, "await": true, "async": true,
}

// scanFile returns the findings for one JS/TS source.
func scanFile(path string, content []byte) []findings.Finding {
	code := codeView(content)
	var out []findings.Finding
	seen := map[int]bool{}
	for _, def := range definitions(code) {
		if seen[def.open] {
			continue
		}
		seen[def.open] = true
		if f, ok := checkFunction(path, content, code, def); ok {
			out = append(out, f)
		}
	}
	return out
}

type definition struct {
	name        string
	open, close int // the body's braces
}

// definitions finds every named function body in the code view.
func definitions(code string) []definition {
	var defs []definition
	add := func(name string, paren int, arrowOK bool) {
		if keywords[name] {
			return
		}
		end := matchClose(code, paren, '(', ')')
		if end < 0 {
			return
		}
		i := skipSpace(code, end+1)
		if i < len(code) && code[i] == ':' { // a return type
			for i < len(code) && code[i] != '{' && code[i] != ';' && code[i] != '=' {
				i++
			}
		}
		i = skipSpace(code, i)
		if arrowOK && strings.HasPrefix(code[i:], "=>") {
			i = skipSpace(code, i+2)
		}
		if i >= len(code) || code[i] != '{' {
			return
		}
		if c := matchClose(code, i, '{', '}'); c > 0 {
			defs = append(defs, definition{name: name, open: i, close: c})
		}
	}
	for _, m := range namedDef.FindAllStringSubmatchIndex(code, -1) {
		add(code[m[2]:m[3]], m[1]-1, false)
	}
	for _, m := range boundDef.FindAllStringSubmatchIndex(code, -1) {
		add(code[m[2]:m[3]], m[1]-1, true)
	}
	return defs
}

// checkFunction reports the definition when its body is an unguarded
// recursive merge.
func checkFunction(path string, content []byte, code string, def definition) (findings.Finding, bool) {
	body := code[def.open:def.close]
	if guardLiteral.Match(content[def.open:def.close]) || guardName.MatchString(body) {
		return findings.Finding{}, false
	}
	var keys []string
	iterated := map[string]string{} // key variable -> the object it iterates
	for _, re := range keyLoops {
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			k := m[re.SubexpIndex("key")]
			keys = append(keys, k)
			if ids := lastIdent.FindAllString(m[re.SubexpIndex("src")], -1); len(ids) > 0 {
				iterated[k] = ids[len(ids)-1]
			}
		}
	}
	if len(keys) == 0 {
		return findings.Finding{}, false
	}
	call := regexp.MustCompile(`(?:^|[^\w$.]|\bthis\.)` + regexp.QuoteMeta(def.name) + `\s*\(`)
	for _, m := range call.FindAllStringIndex(body, -1) {
		paren := def.open + m[1] - 1
		end := matchClose(code, paren, '(', ')')
		if end < 0 {
			continue
		}
		args := code[paren+1 : end]
		// The text the call is assigned to: the statement up to the callee.
		lhs := strings.TrimSpace(code[statementStart(code, paren):paren])
		lhs = strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(lhs, def.name), "this."))
		for _, k := range keys {
			// Only an object written at [key] pollutes: a read or a
			// traversal recursing into it changes nothing.
			written := writtenBases(body, k)
			// Writing into the object whose keys are iterated cannot
			// pollute: inside Object.prototype that loop finds no
			// enumerable key. It takes a source and a separate target.
			delete(written, iterated[k])
			if recursesIntoWritten(body, args, k, written) {
				return finding(path, code, paren, def.name), true
			}
			// target[key] = merge(existing, value) with existing = target[key].
			if b := indexedBase(lhs, k, true); b != "" && written[b] {
				for _, alias := range aliasesOf(body, k, written) {
					if regexp.MustCompile(`(?:^|[^\w$.])` + regexp.QuoteMeta(alias) + `\b`).MatchString(args) {
						return finding(path, code, paren, def.name), true
					}
				}
			}
		}
	}
	return findings.Finding{}, false
}

// baseAt matches B[k] -- B possibly inside a cast, (target as T)[key] -- and
// captures B.
func baseAt(k string) *regexp.Regexp {
	return regexp.MustCompile(`([A-Za-z_$][\w$]*)(?:\s+as\s+[^()\[\]=;]*)?\)?\s*\[\s*` + regexp.QuoteMeta(k) + `\s*\]`)
}

// writtenBases are the objects the body assigns at [k]: target[key] = ...
func writtenBases(body, k string) map[string]bool {
	out := map[string]bool{}
	re := regexp.MustCompile(baseAt(k).String() + `\s*=[^=]`)
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		out[m[1]] = true
	}
	return out
}

// recursesIntoWritten reports whether the recursion's arguments pass a
// written object at [k]: merge(target[key], ...) with target[key] written.
func recursesIntoWritten(body, args, k string, written map[string]bool) bool {
	for _, m := range baseAt(k).FindAllStringSubmatch(args, -1) {
		if written[m[1]] {
			return true
		}
	}
	return false
}

// indexedBase returns B when text is B[k] (assigned: followed by `=` at its
// end), or "".
func indexedBase(text, k string, assigned bool) string {
	re := baseAt(k)
	if assigned {
		re = regexp.MustCompile(re.String() + `\s*=$`)
	}
	if m := re.FindStringSubmatch(text); m != nil {
		return m[1]
	}
	return ""
}

// aliasesOf are the names bound from a written object at [k]:
// const existing = target[key].
func aliasesOf(body, k string, written map[string]bool) []string {
	re := regexp.MustCompile(`(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;]*)?=\s*` + baseAt(k).String())
	var out []string
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		if written[m[2]] {
			out = append(out, m[1])
		}
	}
	return out
}

func finding(path, code string, at int, name string) findings.Finding {
	line := strings.Count(code[:at], "\n") + 1
	return findings.Finding{
		RuleID:     ruleID,
		Severity:   findings.SeverityMedium,
		Confidence: findings.ConfidenceMedium,
		Message: "Recursive merge " + name + " walks into target[key] for every key of its input with no " +
			"__proto__/constructor guard: a \"__proto__\" key pollutes Object.prototype (CWE-1321)",
		Location: findings.Location{FilePath: path, StartLine: line, EndLine: line},
		Metadata: map[string]string{"cwe": "CWE-1321", "function": name},
	}
}

// codeView blanks strings and comments, keeping offsets and newlines.
func codeView(content []byte) string {
	b := []byte(string(content))
	for _, r := range lexctx.Classify(lexctx.LangJavaScript, content) {
		if r.Kind == lexctx.KindCode {
			continue
		}
		for i := r.Start; i < r.End && i < len(b); i++ {
			if b[i] != '\n' {
				b[i] = ' '
			}
		}
	}
	return string(b)
}

// matchClose returns the index of the bracket closing the one at open.
func matchClose(s string, open int, o, c byte) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case o:
			depth++
		case c:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func skipSpace(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	return i
}

// statementStart is where the statement holding offset at begins.
func statementStart(code string, at int) int {
	for i := at - 1; i >= 0; i-- {
		if c := code[i]; c == ';' || c == '{' || c == '}' {
			return i + 1
		}
	}
	return 0
}
