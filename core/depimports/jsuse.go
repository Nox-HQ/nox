package depimports

import (
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/lexctx"
)

// JS and TypeScript symbol usage.
//
// Importing a package (Index.Imports) says the project links it. This says the
// project REFERENCES one named export of it: `import { sendMail } from 'x'`
// followed by a use of sendMail, `const x = require('m'); x.send()`,
// `const { a: b } = require('m'); b()`, `import * as ns from 'm'; ns.f`,
// `require('m').f()`, `const m = await import('m'); m.f` and the TypeScript
// `import x = require('m')`.
//
// # Only ever positive
//
// A fact here is recorded only for a reference that was actually read in code.
// The absence of a fact is not "unused": a binding can be passed to another
// function, re-exported, reached through a class instance, spread, or used
// through a dependency, none of which is followed. Callers must treat a miss as
// "nothing found", never as a reason to lower anything.
//
// What is skipped on purpose, because it would invent a use: comments and string
// bodies (masked), `import type` and inline `type` members, test, spec, mock
// and fixture paths, relative imports and `node:` builtins, property accesses of
// the same name on another object (`other.sendMail`), and object-literal keys.

// JSUse is where a project source file references an export.
type JSUse struct {
	File string
	Line int
}

var (
	jsESMImport = regexp.MustCompile("(?:^|[^\\w$.])import\\s+(type\\s+)?([^;'\"`(]*?)\\bfrom\\s*([\"'])")
	jsTSRequire = regexp.MustCompile(`(?:^|[^\w$.])import\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*(["'])`)
	jsBinding   = regexp.MustCompile(`(?:^|[^\w$.])(\{[^{}]*\}|[A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?(require|import)\s*\(\s*(["'])`)
	jsDirect    = regexp.MustCompile(`(?:^|[^\w$.])(require|import)\s*\(\s*(["'])`)
	jsMemberRe  = regexp.MustCompile(`^\s*\??\.\s*([A-Za-z_$][\w$]*)`)
	jsBracketRe = regexp.MustCompile(`^\s*\[\s*(?:"([^"\\\n]+)"|'([^'\\\n]+)')\s*\]`)
)

type jsBind struct {
	whole    bool   // the local is the module value itself
	imported string // for a named binding: the export name
	local    string
}

// addJSUses reads one JS/TS file's references into the index.
func (ix *Index) addJSUses(file string, content []byte) {
	if isNonProductionPath(file) {
		return
	}
	masked := lexctx.MaskNonCode(lexctx.LangJavaScript, content)
	m := string(masked)
	lines := lineStarts(content)
	var skip [][2]int
	record := func(spec, name string, off int) {
		pkg := npmPackage(spec)
		if pkg == "" || name == "" {
			return
		}
		ix.recordUse(normalizeSpec(spec), name, JSUse{File: file, Line: lineOf(lines, off)})
	}
	type pending struct {
		spec string
		b    []jsBind
	}
	var binds []pending
	consumed := map[int]bool{} // offsets of require/import keywords owned by a binding

	// ESM: import ... from 'm'
	for _, mm := range jsESMImport.FindAllStringSubmatchIndex(m, -1) {
		if mm[2] >= 0 { // import type
			continue
		}
		q := mm[6]
		spec, ok := specAt(content, m, q)
		if !ok {
			continue
		}
		skip = append(skip, [2]int{mm[0], q + len(spec) + 2})
		binds = append(binds, pending{spec, parseImportClause(m[mm[4]:mm[5]])})
	}
	// TypeScript: import x = require('m')
	for _, mm := range jsTSRequire.FindAllStringSubmatchIndex(m, -1) {
		q := mm[4]
		spec, ok := specAt(content, m, q)
		if !ok {
			continue
		}
		skip = append(skip, [2]int{mm[0], q + len(spec) + 2})
		consumed[kwOffset(m, mm[0], "require")] = true
		binds = append(binds, pending{spec, []jsBind{{whole: true, local: m[mm[2]:mm[3]]}}})
	}
	// CommonJS and dynamic import with a left-hand side.
	for _, mm := range jsBinding.FindAllStringSubmatchIndex(m, -1) {
		q := mm[6]
		spec, ok := specAt(content, m, q)
		if !ok {
			continue
		}
		kwStart := strings.LastIndex(m[mm[0]:q], m[mm[4]:mm[5]]) + mm[0]
		consumed[kwStart] = true
		closeAt := afterCall(m, q+len(spec)+1)
		lhs := m[mm[2]:mm[3]]
		tail := m[closeAt:]
		skip = append(skip, [2]int{mm[0], closeAt})
		switch {
		case strings.HasPrefix(strings.TrimLeft(tail, " \t"), "(") && m[mm[4]:mm[5]] == "require":
			// require('m')(opts): the left side is the RESULT of calling the module.
			record(spec, "default", closeAt)
		case jsMemberRe.MatchString(tail) && !strings.HasPrefix(lhs, "{"):
			mem := jsMemberRe.FindStringSubmatch(tail)[1]
			if mem == "then" || mem == "catch" || mem == "finally" {
				continue
			}
			binds = append(binds, pending{spec, []jsBind{{imported: mem, local: lhs}}})
		case strings.HasPrefix(lhs, "{"):
			binds = append(binds, pending{spec, parseDestructure(lhs)})
		default:
			binds = append(binds, pending{spec, []jsBind{{whole: true, local: lhs}}})
		}
	}
	// A module used in place: require('m').f, require('m')(...)
	for _, mm := range jsDirect.FindAllStringSubmatchIndex(m, -1) {
		kw := mm[2]
		if consumed[kw] {
			continue
		}
		q := mm[4]
		spec, ok := specAt(content, m, q)
		if !ok {
			continue
		}
		tail := m[afterCall(m, q+len(spec)+1):]
		if m[mm[2]:mm[3]] == "require" && strings.HasPrefix(strings.TrimLeft(tail, " \t"), "(") {
			record(spec, "default", kw)
			continue
		}
		if mem := jsMemberRe.FindStringSubmatch(tail); len(mem) > 1 && mem[1] != "then" && mem[1] != "catch" && mem[1] != "finally" {
			record(spec, mem[1], kw)
		}
	}
	sort.Slice(skip, func(i, j int) bool { return skip[i][0] < skip[j][0] })

	for _, p := range binds {
		for _, b := range p.b {
			if b.local == "" || !isSimpleJSIdent(b.local) {
				continue
			}
			ix.scanLocal(m, content, lines, skip, p.spec, b, record)
		}
	}
}

// scanLocal finds the references to one imported local.
func (ix *Index) scanLocal(m string, content []byte, lines []int, skip [][2]int, spec string, b jsBind, record func(spec, name string, off int)) {
	for _, off := range identOccurrences(m, b.local) {
		if inSpans(skip, off) || declaresOrKeys(m, off, b.local) {
			continue
		}
		if !b.whole {
			record(spec, b.imported, off)
			continue
		}
		rest := m[off+len(b.local):]
		if mem := jsMemberRe.FindStringSubmatch(rest); mem != nil {
			record(spec, mem[1], off)
			continue
		}
		if br := jsBracketRe.FindSubmatch(content[off+len(b.local):]); br != nil {
			name := string(br[1])
			if name == "" {
				name = string(br[2])
			}
			record(spec, name, off)
			continue
		}
		if strings.HasPrefix(strings.TrimLeft(rest, " \t"), "(") {
			record(spec, "default", off)
		}
	}
	if !b.whole {
		return
	}
	re := regexp.MustCompile(`(?:^|[^\w$.])(\{[^{}]*\})\s*=\s*` + regexp.QuoteMeta(b.local) + `(?:[^\w$]|$)`)
	for _, mm := range re.FindAllStringSubmatchIndex(m, -1) {
		for _, d := range parseDestructure(m[mm[2]:mm[3]]) {
			record(spec, d.imported, mm[2])
		}
	}
}

// JSSymbolUse reports whether non-test project source references the export
// `name` of the module imported as `spec` (`lodash`, `lodash/fp`, `@a/b/sub`).
// The name "default" is the module value itself, called directly.
func (ix *Index) JSSymbolUse(spec, name string) (JSUse, bool) {
	u, ok := ix.jsUses[normalizeSpec(spec)][name]
	return u, ok
}

func (ix *Index) recordUse(spec, name string, u JSUse) {
	if ix.jsUses == nil {
		ix.jsUses = map[string]map[string]JSUse{}
	}
	byName := ix.jsUses[spec]
	if byName == nil {
		byName = map[string]JSUse{}
		ix.jsUses[spec] = byName
	}
	// Files arrive in discovery order; keep the smallest so the witness does
	// not depend on it.
	if old, ok := byName[name]; ok && (old.File < u.File || (old.File == u.File && old.Line <= u.Line)) {
		return
	}
	byName[name] = u
}

// normalizeSpec reduces a specifier to the spelling an advisory's symbol uses:
// no query, no extension, no trailing index or slash.
func normalizeSpec(spec string) string {
	if i := strings.IndexAny(spec, "?#"); i >= 0 {
		spec = spec[:i]
	}
	spec = strings.TrimSuffix(spec, "/")
	switch strings.ToLower(path.Ext(spec)) {
	case ".js", ".cjs", ".mjs", ".ts", ".mts", ".cts", ".jsx", ".tsx":
		spec = strings.TrimSuffix(spec, path.Ext(spec))
	}
	spec = strings.TrimSuffix(spec, "/index")
	return strings.ToLower(spec)
}

// NormalizeSpecifier is normalizeSpec for callers outside the package.
func NormalizeSpecifier(spec string) string { return normalizeSpec(spec) }

func parseImportClause(clause string) []jsBind {
	clause = strings.TrimSpace(clause)
	var out []jsBind
	for clause != "" {
		switch {
		case strings.HasPrefix(clause, "*"):
			f := strings.Fields(strings.TrimPrefix(clause, "*"))
			if len(f) >= 2 && f[0] == "as" {
				out = append(out, jsBind{whole: true, local: strings.TrimRight(f[1], ",")})
			}
			return out
		case strings.HasPrefix(clause, "{"):
			end := strings.Index(clause, "}")
			if end < 0 {
				return out
			}
			for _, part := range strings.Split(clause[1:end], ",") {
				f := strings.Fields(part)
				if len(f) == 0 || f[0] == "type" && len(f) >= 2 && (len(f) == 2 || f[2] == "as") {
					continue // inline `type X`
				}
				local := f[0]
				if len(f) == 3 && f[1] == "as" {
					local = f[2]
				}
				out = append(out, jsBind{imported: f[0], local: local})
			}
			return out
		default:
			i := strings.IndexAny(clause, ", \t\r\n")
			ident := clause
			if i >= 0 {
				ident = clause[:i]
			}
			if isSimpleJSIdent(ident) {
				out = append(out, jsBind{whole: true, local: ident})
			}
			if i < 0 {
				return out
			}
			clause = strings.TrimLeft(strings.TrimLeft(clause[i:], " \t\r\n"), ",")
			clause = strings.TrimSpace(clause)
		}
	}
	return out
}

func parseDestructure(pat string) []jsBind {
	pat = strings.TrimSpace(strings.Trim(strings.TrimSpace(pat), "{}"))
	var out []jsBind
	for _, part := range strings.Split(pat, ",") {
		part = strings.TrimSpace(part)
		if part == "" || strings.HasPrefix(part, "...") || strings.ContainsAny(part, "{[") {
			continue
		}
		if i := strings.Index(part, "="); i >= 0 {
			part = strings.TrimSpace(part[:i])
		}
		name, local := part, part
		if i := strings.Index(part, ":"); i >= 0 {
			name, local = strings.TrimSpace(part[:i]), strings.TrimSpace(part[i+1:])
		}
		if isSimpleJSIdent(name) && isSimpleJSIdent(local) {
			out = append(out, jsBind{imported: name, local: local})
		}
	}
	return out
}

// specAt reads the string literal whose opening quote is at q. The masked text
// keeps delimiters, so the closing quote is the next one of the same kind.
func specAt(content []byte, masked string, q int) (string, bool) {
	if q >= len(masked) {
		return "", false
	}
	end := strings.IndexByte(masked[q+1:], masked[q])
	if end < 0 {
		return "", false
	}
	s := string(content[q+1 : q+1+end])
	if s == "" || strings.ContainsAny(s, "\n\r") {
		return "", false
	}
	return s, true
}

// afterCall returns the offset just past the `)` that closes a call whose
// string argument ends at closeQuote.
func afterCall(m string, closeQuote int) int {
	i := closeQuote + 1
	for i < len(m) && (m[i] == ' ' || m[i] == '\t' || m[i] == '\n' || m[i] == '\r') {
		i++
	}
	if i < len(m) && m[i] == ')' {
		return i + 1
	}
	return closeQuote + 1
}

func kwOffset(m string, from int, kw string) int {
	if i := strings.Index(m[from:], kw); i >= 0 {
		return from + i
	}
	return from
}

func isSimpleJSIdent(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if i == 0 && c >= '0' && c <= '9' || !isIdentByte(c) {
			return false
		}
	}
	return true
}

func isIdentByte(c byte) bool {
	return c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// identOccurrences finds name as a whole identifier that is not a property of
// something else.
func identOccurrences(m, name string) []int {
	var out []int
	for from := 0; ; {
		i := strings.Index(m[from:], name)
		if i < 0 {
			return out
		}
		at := from + i
		from = at + len(name)
		if at > 0 && (isIdentByte(m[at-1]) || m[at-1] == '.') {
			continue
		}
		if at+len(name) < len(m) && isIdentByte(m[at+len(name)]) {
			continue
		}
		out = append(out, at)
	}
}

func inSpans(spans [][2]int, off int) bool {
	for _, s := range spans {
		if off >= s[0] && off < s[1] {
			return true
		}
	}
	return false
}

var declKeywords = map[string]bool{"function": true, "class": true, "const": true, "let": true, "var": true,
	"interface": true, "type": true, "enum": true, "namespace": true}

// declaresOrKeys is true for an occurrence that is not a use of the import: a
// redeclaration that shadows it, or an object-literal key.
func declaresOrKeys(m string, off int, name string) bool {
	j := off - 1
	for j >= 0 && (m[j] == ' ' || m[j] == '\t' || m[j] == '\n' || m[j] == '\r') {
		j--
	}
	end := j + 1
	for j >= 0 && isIdentByte(m[j]) {
		j--
	}
	if declKeywords[m[j+1:end]] {
		return true
	}
	prev := byte(0)
	if end > 0 {
		prev = m[end-1]
	}
	k := off + len(name)
	for k < len(m) && (m[k] == ' ' || m[k] == '\t') {
		k++
	}
	return k < len(m) && m[k] == ':' && (prev == '{' || prev == ',') && (k+1 >= len(m) || m[k+1] != ':')
}

func lineStarts(content []byte) []int {
	out := []int{0}
	for i, c := range content {
		if c == '\n' {
			out = append(out, i+1)
		}
	}
	return out
}

func lineOf(starts []int, off int) int {
	return sort.Search(len(starts), func(i int) bool { return starts[i] > off })
}

// isNonProductionPath reports tests, mocks, fixtures and stories: a reference
// there says the test suite exercises a symbol, not that the application does.
func isNonProductionPath(p string) bool {
	p = strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case "test", "tests", "__tests__", "__mocks__", "__fixtures__", "fixtures", "e2e", "spec", "specs", "cypress", "stories", "node_modules":
			return true
		}
	}
	base := path.Base(p)
	for _, mark := range []string{".test.", ".spec.", ".stories.", ".e2e.", ".mock."} {
		if strings.Contains(base, mark) {
			return true
		}
	}
	return false
}
