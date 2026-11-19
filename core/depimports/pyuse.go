package depimports

import (
	"path"
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/lexctx"
)

// Python symbol usage.
//
// Importing a distribution (Index.Imports) says the project imports it. This
// says the project REFERENCES one function or class of one of its modules:
// `from PIL.Image import open` followed by a use of open, `from PIL import
// Image; Image.open(...)`, `import yaml; yaml.load(...)`, `import a.b as c;
// c.f(...)` and attribute chains such as `requests.sessions.Session`.
//
// # Only ever positive
//
// As in jsuse.go, a fact is recorded only for a reference read in code, and its
// absence means nothing: a function can be passed on, re-exported from a
// package's __init__ (requests.get is defined in requests.api), reached through
// an instance, or called by a dependency. Callers must treat a miss as "nothing
// found", never as a reason to lower anything.
//
// Skipped on purpose, because each would invent a use: comments and string
// bodies (masked), an import with no later reference, relative imports, star
// imports, attribute accesses of the same name on another object, and test
// files (tests/, test_*.py, *_test.py, conftest.py).

var (
	pyFromStmt   = regexp.MustCompile(`(?m)^[ \t]*from[ \t]+([A-Za-z_][\w.]*)[ \t]+import[ \t]+(\([^)]*\)|[^\n]*)`)
	pyImportStmt = regexp.MustCompile(`(?m)^[ \t]*import[ \t]+([^\n]*)`)
	pyAlias      = regexp.MustCompile(`^([A-Za-z_][\w.]*)(?:\s+as\s+([A-Za-z_]\w*))?$`)
	pyAttr       = regexp.MustCompile(`^\.\s*([A-Za-z_]\w*)`)
)

// pyBind is a local name bound by an import: to a module, or to a member of
// one. `from a import b` binds both readings, because b may be either.
type pyBind struct {
	local  string
	module string // the module the local IS, when it is one
	owner  string // for a member binding: the module that defines it
	member string
}

// addPyUses reads one Python file's references into the index.
func (ix *Index) addPyUses(file string, content []byte) {
	if isNonProductionPath(file) || isPythonTestFile(file) {
		return
	}
	m := string(lexctx.MaskNonCode(lexctx.LangPython, content))
	lines := lineStarts(content)
	var skip [][2]int
	var binds []pyBind

	for _, mm := range pyFromStmt.FindAllStringSubmatchIndex(m, -1) {
		skip = append(skip, [2]int{mm[0], mm[1]})
		mod := m[mm[2]:mm[3]]
		for _, item := range splitPyNames(m[mm[4]:mm[5]]) {
			a := pyAlias.FindStringSubmatch(item)
			if len(a) < 2 || strings.Contains(a[1], ".") {
				continue // star import, or not a name
			}
			local := a[1]
			if a[2] != "" {
				local = a[2]
			}
			binds = append(binds, pyBind{local: local, owner: mod, member: a[1], module: mod + "." + a[1]})
		}
	}
	for _, mm := range pyImportStmt.FindAllStringSubmatchIndex(m, -1) {
		skip = append(skip, [2]int{mm[0], mm[1]})
		for _, item := range splitPyNames(m[mm[2]:mm[3]]) {
			a := pyAlias.FindStringSubmatch(item)
			if len(a) < 3 {
				continue
			}
			if a[2] != "" {
				binds = append(binds, pyBind{local: a[2], module: a[1]})
				continue
			}
			// `import a.b.c` binds a; the chain names the rest.
			top := topSegment(a[1])
			binds = append(binds, pyBind{local: top, module: top})
		}
	}

	record := func(module, name string, off int) {
		ix.recordPyUse(module, name, JSUse{File: file, Line: lineOf(lines, off)})
	}
	for _, b := range binds {
		for _, at := range identOccurrences(m, b.local) {
			if inSpans(skip, at) {
				continue
			}
			if b.member != "" {
				record(b.owner, b.member, at)
			}
			// Follow the attribute chain: a.b.c records (a, b) and (a.b, c).
			mod, rest := b.module, m[at+len(b.local):]
			for {
				attr := pyAttr.FindStringSubmatch(rest)
				if attr == nil {
					break
				}
				record(mod, attr[1], at)
				rest = rest[len(attr[0]):]
				mod += "." + attr[1]
			}
		}
	}
}

// splitPyNames splits an import list, with or without parentheses, into its
// items. A trailing comment was masked; a backslash continuation is joined.
func splitPyNames(list string) []string {
	list = strings.NewReplacer("(", " ", ")", " ", "\\\n", " ", "\n", " ").Replace(list)
	var out []string
	for _, it := range strings.Split(list, ",") {
		it = strings.Join(strings.Fields(it), " ")
		if it != "" {
			out = append(out, it)
		}
	}
	return out
}

// isPythonTestFile reports pytest's file conventions.
func isPythonTestFile(p string) bool {
	base := strings.ToLower(path.Base(strings.ReplaceAll(p, "\\", "/")))
	return base == "conftest.py" || strings.HasPrefix(base, "test_") || strings.HasSuffix(base, "_test.py")
}

// PySymbolUse reports whether non-test project source references the function
// or class `name` of the Python module `module` (`PIL.Image`, `yaml`).
func (ix *Index) PySymbolUse(module, name string) (JSUse, bool) {
	u, ok := ix.pyUses[module][name]
	return u, ok
}

func (ix *Index) recordPyUse(module, name string, u JSUse) {
	if ix.pyUses == nil {
		ix.pyUses = map[string]map[string]JSUse{}
	}
	byName := ix.pyUses[module]
	if byName == nil {
		byName = map[string]JSUse{}
		ix.pyUses[module] = byName
	}
	// Keep the smallest witness so it does not depend on discovery order.
	if old, ok := byName[name]; ok && (old.File < u.File || (old.File == u.File && old.Line <= u.Line)) {
		return
	}
	byName[name] = u
}
