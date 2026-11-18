package engine

import (
	"slices"
	"strings"

	"github.com/nox-hq/nox/core/taint"
)

// A sanitizer can be a property read rather than a call: Swift's and
// Objective-C's `url.lastPathComponent` strips the directories off a path, and
// there are no parens to give the extractor a call. The catalog declares it as
// a sanitizer, but every place the engine honours one looks at a statement's
// Calls, so `URL(string: p)?.lastPathComponent` cleared nothing and the
// idiomatic guard was reported as the vulnerability it prevents.
//
// withPropertySanitizers closes that without a second sanitizer model: for each
// catalog sanitizer of the language that is a single bare name, a `.name` read
// that is not a call is recorded as a call of that name over the variables its
// receiver reads, which is exactly what the call form `name(receiver)` would
// have recorded. Only sanitizers the catalog already declares are recognized,
// and a name the catalog does not list for the language is never touched.

// withPropertySanitizers returns units with property-form sanitizers recorded
// as calls. The input is not modified; a unit with nothing to record is
// returned as is.
func (e *StructuralEngine) withPropertySanitizers(units []taint.Unit) []taint.Unit {
	if len(units) == 0 {
		return units
	}
	names := e.propertySanitizerNames(units[0].Language)
	if len(names) == 0 {
		return units
	}
	out := make([]taint.Unit, len(units))
	for i := range units {
		out[i] = units[i]
		var stmts []taint.Statement
		for j := range units[i].Stmts {
			st, changed := recordPropertySanitizers(units[i].Stmts[j], names)
			if changed && stmts == nil {
				stmts = slices.Clone(units[i].Stmts)
			}
			if changed {
				stmts[j] = st
			}
		}
		if stmts != nil {
			out[i].Stmts = stmts
		}
	}
	return out
}

// propertySanitizerLangs are the languages where a property read is a sanitizer
// idiom (Foundation's URL/NSString `lastPathComponent`). In the others a bare
// `.int` or `.escape` is an attribute that happens to share a name with a
// sanitizer function, so recognizing it would silence flows it should not.
var propertySanitizerLangs = map[string]bool{"swift": true, "objc": true}

// propertySanitizerNames lists the catalog sanitizers of lang that can be read
// as a property: a bare identifier, no dots, in a language that has them.
func (e *StructuralEngine) propertySanitizerNames(lang string) []string {
	if !propertySanitizerLangs[lang] {
		return nil
	}
	var names []string
	for _, s := range e.cat.Sanitizers(lang) {
		if isBareIdent(s.Call) && !slices.Contains(names, s.Call) {
			names = append(names, s.Call)
		}
	}
	slices.Sort(names)
	return names
}

// recordPropertySanitizers adds the property reads found in st's expression and
// call arguments. changed is false when st had none.
func recordPropertySanitizers(st taint.Statement, names []string) (taint.Statement, bool) {
	texts := []string{st.Expr}
	for _, k := range sortedKeys(st.SinkArgs) {
		texts = append(texts, st.SinkArgs[k].PositionalArgs...)
	}
	found := map[string][]string{}
	for _, text := range texts {
		for _, name := range names {
			for _, recv := range propertyReceivers(text, name) {
				for _, id := range freeIdentifiers(langPython, recv) {
					if slices.Contains(st.Reads, id) && !slices.Contains(found[name], id) {
						found[name] = append(found[name], id)
					}
				}
				if _, ok := found[name]; !ok {
					found[name] = nil
				}
			}
		}
	}
	if len(found) == 0 {
		return st, false
	}
	st.Calls = slices.Clone(st.Calls)
	args := make(map[string]taint.SinkArgInfo, len(st.SinkArgs)+len(found))
	for k, v := range st.SinkArgs {
		args[k] = v
	}
	for _, name := range names {
		vars, ok := found[name]
		if !ok {
			continue
		}
		slices.Sort(vars)
		if !slices.Contains(st.Calls, name) {
			st.Calls = append(st.Calls, name)
		}
		info := args[name]
		info.TaintedArgVars = append(info.TaintedArgVars, vars...)
		args[name] = info
	}
	st.SinkArgs = args
	return st, true
}

func sortedKeys(m map[string]taint.SinkArgInfo) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// propertyReceivers returns the receiver text of every `.name` read in code
// that is not a call: the identifier chain, or the call or subscript chain,
// ending just before the dot. `URL(string: p)?.lastPathComponent` yields
// `URL(string: p)`; `p.lastPathComponent` yields `p`.
func propertyReceivers(code, name string) []string {
	var out []string
	for from := 0; ; {
		i := strings.Index(code[from:], "."+name)
		if i < 0 {
			return out
		}
		dot := from + i
		from = dot + 1
		end := dot + 1 + len(name)
		if end < len(code) && isIdentPart(code[end]) {
			continue
		}
		if rest := strings.TrimLeft(code[end:], " \t"); strings.HasPrefix(rest, "(") {
			continue // the call form, already seen as a call
		}
		out = append(out, receiverBefore(code, dot))
	}
}

// receiverBefore returns the member-access chain that ends just before the
// dot at code[dot], stepping over balanced parens and brackets and the `?`/`!`
// optional markers.
func receiverBefore(code string, dot int) string {
	i := dot
	for i > 0 {
		c := code[i-1]
		switch {
		case isIdentPart(c) || c == '.' || c == '?' || c == '!':
			i--
		case c == ')' || c == ']':
			open := matchingOpenBefore(code, i-1)
			if open < 0 {
				return code[i:dot]
			}
			i = open
		default:
			return code[i:dot]
		}
	}
	return code[i:dot]
}

// matchingOpenBefore finds the opener that pairs with the closer at code[at].
func matchingOpenBefore(code string, at int) int {
	depth := 0
	for i := at; i >= 0; i-- {
		switch code[i] {
		case ')', ']':
			depth++
		case '(', '[':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}
