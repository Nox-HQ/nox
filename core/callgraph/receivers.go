package callgraph

import (
	"regexp"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/lexctx"
)

// Receiver types: a call on a field or parameter whose declared type names a
// project class.
//
// A controller hands request input to a service it holds in a field:
//
//	private final StaffDirectoryService directory;           // Java, Spring
//	constructor(private readonly svc: AttachmentsService) {} // TypeScript, NestJS
//	self.repo = UserRepository(db)                           // Python
//
// and calls `directory.findByEmployeeNumber(n)`. The method's receiver is a
// value, so the qualifier names no module; but the file states the value's
// type. receiverTypes reads those declarations, and a call on a name declared
// with exactly one type binds to that type's method:
//
//   - in the one project file that declares a class of that name, when that
//     file has the method;
//   - otherwise (an interface, or an abstract base) in the one class that
//     implements or extends it and has the method.
//
// A name the file declares with two different types, a type two files
// declare, or two implementations: none of them binds. The graph never
// guesses which object a call reaches.

// classDecl is a class, interface, record or enum a file declares, with the
// types it names as its supertypes.
type classDecl struct {
	name   string
	supers []string
}

var (
	// Java: `Type name` followed by the end of a declaration or parameter:
	// `private final Svc svc;`, `Svc svc = ...`, `(Svc svc, ...)`. Generic
	// arguments are skipped: `Repo<User> users;` is a Repo.
	javaDeclRe = regexp.MustCompile(`\b([A-Z][A-Za-z0-9_]*)\s*(?:<[^;(){}=]*>)?\s+([a-z_][A-Za-z0-9_]*)\s*[;,)=]`)
	// TypeScript: `name: Type` in a field, a parameter or a constructor
	// parameter property (`private readonly svc: Svc`).
	tsDeclRe = regexp.MustCompile(`\b([A-Za-z_$][A-Za-z0-9_$]*)\s*[?!]?\s*:\s*([A-Z][A-Za-z0-9_$]*)\b`)
	// Python annotations: `repo: UserRepository`.
	pyAnnRe = regexp.MustCompile(`\b([a-z_][A-Za-z0-9_]*)\s*:\s*([A-Z][A-Za-z0-9_]*)\b`)
	// Every language read here: `name = new Type(` (Java, JavaScript),
	// `self.name = Type(` and `name = Type(` (Python).
	newRe    = regexp.MustCompile(`\b([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*new\s+([A-Z][A-Za-z0-9_$]*)\s*[(<]`)
	pyCallRe = regexp.MustCompile(`\b([a-z_][A-Za-z0-9_]*)\s*=\s*([A-Z][A-Za-z0-9_]*)\s*\(`)

	// A class header up to its body: `class A extends B implements C, D {`.
	classRe = regexp.MustCompile(`\b(?:class|interface|record|enum)\s+([A-Z][A-Za-z0-9_$]*)([^{;]*)[{:]`)
	nameRe  = regexp.MustCompile(`[A-Z][A-Za-z0-9_$]*`)
)

// receiverTypes returns the declared type of each name the file declares with
// exactly one type, and the classes the file declares. Comments and string
// literals are masked first, so neither a commented-out field nor a type named
// in a message is read as a declaration.
func receiverTypes(lang string, content []byte) (map[string]string, []classDecl) {
	var lx lexctx.Lang
	var declRes []*regexp.Regexp
	switch strings.ToLower(lang) {
	case "java":
		lx, declRes = lexctx.LangJava, []*regexp.Regexp{javaDeclRe, newRe}
	case "typescript", "javascript":
		lx, declRes = lexctx.LangJavaScript, []*regexp.Regexp{tsDeclRe, newRe}
	case "python":
		lx, declRes = lexctx.LangPython, []*regexp.Regexp{pyAnnRe, pyCallRe}
	default:
		return nil, nil
	}
	code := lexctx.MaskNonCode(lx, content)
	seen := map[string]map[string]bool{}
	for _, re := range declRes {
		for _, m := range re.FindAllSubmatch(code, -1) {
			name, typ := string(m[1]), string(m[2])
			if re == javaDeclRe {
				typ, name = name, typ
			}
			if javaKeywords[name] || typ == "" {
				continue
			}
			if seen[name] == nil {
				seen[name] = map[string]bool{}
			}
			seen[name][typ] = true
		}
	}
	types := map[string]string{}
	for name, ts := range seen {
		if len(ts) == 1 {
			for t := range ts {
				types[name] = t
			}
		}
	}
	var classes []classDecl
	for _, m := range classRe.FindAllSubmatch(code, -1) {
		c := classDecl{name: string(m[1])}
		header := string(m[2])
		// Generic parameters are not supertypes: `class Repo<T extends Base>`.
		if i := strings.IndexAny(header, "<"); i >= 0 && !strings.Contains(header[:i], "extends") && !strings.Contains(header[:i], "implements") {
			if j := strings.LastIndex(header, ">"); j > i {
				header = header[:i] + header[j+1:]
			}
		}
		for _, s := range nameRe.FindAllString(header, -1) {
			if s != c.name {
				c.supers = append(c.supers, s)
			}
		}
		classes = append(classes, c)
	}
	return types, classes
}

// javaKeywords are words the declaration pattern can mistake for a name.
var javaKeywords = map[string]bool{
	"return": true, "new": true, "throw": true, "else": true, "case": true, "extends": true,
	"implements": true, "instanceof": true, "import": true, "package": true,
}

// receiverField is the field or variable a qualifier calls through: `svc`,
// `this.svc`, `self.svc`. A deeper chain (`a.b.c`) is a value this graph does
// not type.
func receiverField(qual string) string {
	q := qual
	for _, p := range []string{"this.", "self.", "@"} {
		q = strings.TrimPrefix(q, p)
	}
	if q == "" || strings.ContainsAny(q, "./()[] ") {
		return ""
	}
	return q
}

// addClasses indexes a file's classes by name and by supertype.
func (ix *sourceIndex) addClasses(f *sourceFile) {
	if ix.classes[f.lang] == nil {
		ix.classes[f.lang] = map[string][]string{}
		ix.subtypes[f.lang] = map[string][]string{}
	}
	for _, c := range f.classes {
		ix.classes[f.lang][c.name] = appendUnique(ix.classes[f.lang][c.name], f.path)
		for _, s := range c.supers {
			ix.subtypes[f.lang][s] = appendUnique(ix.subtypes[f.lang][s], f.path)
		}
	}
}

// byReceiverType binds `recv.name(...)` through recv's declared type.
func (ix *sourceIndex) byReceiverType(f *sourceFile, qual, name string) (string, bool) {
	recv := receiverField(qual)
	if recv == "" {
		return "", false
	}
	typ := f.receivers[recv]
	if typ == "" {
		return "", false
	}
	decl, ok := one(ix.classes[f.lang][typ])
	if !ok {
		return "", false
	}
	if keys := ix.byFile[decl][name]; len(keys) > 0 {
		return one(keys)
	}
	// An interface or abstract type: the one subtype that has the method.
	var keys []string
	for _, sub := range ix.subtypes[f.lang][typ] {
		if sub == decl {
			continue
		}
		keys = append(keys, ix.byFile[sub][name]...)
	}
	sort.Strings(keys)
	return one(keys)
}
