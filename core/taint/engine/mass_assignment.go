package engine

import (
	"regexp"
	"slices"
	"strings"

	"github.com/nox-hq/nox/core/taint"
)

// Mass assignment (CWE-915) needs more than taint: the value written must be
// the WHOLE request object, so that every field the client sends lands on the
// record. taintInfo.whole marks such a value. It is set where a variable is
// bound to a whole-object source -- the request body itself, or a handler
// parameter bound to the whole body -- and kept only through copies that keep
// every field (`x = y`, `{ ...y }`, a cast). A field read from it, or anything
// computed from it, is the application choosing what to write.

// requestBoundBodyObject is the sentinel for a handler parameter bound to the
// whole request body (NestJS `@Body() dto`), as opposed to one field of it
// (`@Body('name') name`, RequestBoundBody).
const requestBoundBodyObject = "RequestBoundBodyObject"

// wholeObjectSources are the source expressions that are the whole request
// body, per language.
var wholeObjectSources = map[string]map[string]bool{
	"javascript": {
		"req.body": true, "request.body": true, "ctx.request.body": true,
		"JSON.parse(event.body)": true,
	},
	"python": {
		"request.json": true, "request.get_json()": true, "request.form": true,
		"request.form.to_dict()": true, "request.POST": true, "request.POST.dict()": true,
		"request.POST.copy()": true, "request.data": true, "request.json()": true,
	},
}

// pyWholeJSON is the request body parsed as JSON: json.loads(request.body),
// json.loads(request.body.decode("utf-8") or "{}"), request.get_json(force=True).
var pyWholeJSON = regexp.MustCompile(`^(?:json\.loads\(\s*request\.(?:body|data|get_data\(\))\b|request\.get_json\()`)

// kwargsSplatCall is the synthetic call recorded for a Python call that
// passes **x: the mapping's keys become the callee's keyword arguments, so a
// whole request mapping sets whatever fields the client named.
const kwargsSplatCall = "kwargs_splat"

// isWholeExpr reports whether an expression is the whole request object.
func isWholeExpr(lang, expr string) bool {
	e := wholeExpr(expr)
	if lang == "python" {
		e = strings.TrimSpace(strings.TrimPrefix(e, "**"))
		if pyWholeJSON.MatchString(e) {
			return true
		}
	}
	return wholeObjectSources[lang][e]
}

// itemsOfWhole reports whether a loop binding iterates the keys or items of a
// whole request mapping -- `for k, v in request.json.items()`, `for k in
// data` with data whole -- so its names are the ones the client sent.
func itemsOfWhole(lang, expr string, tainted map[string]taintInfo) bool {
	if lang != "python" {
		return false // a JavaScript destructured name is a field
	}
	e := wholeExpr(expr)
	for _, s := range []string{".items()", ".keys()", ".iteritems()"} {
		e = strings.TrimSuffix(e, s)
	}
	if isWholeExpr(lang, e) {
		return true
	}
	ti, ok := tainted[e]
	return ok && ti.whole
}

// applyKwargsSplats records the splat sink on every Python statement whose
// call passes a **mapping, beside the call itself.
func applyKwargsSplats(drafts []unitDraft) {
	for i := range drafts {
		for j := range drafts[i].stmts {
			st := &drafts[i].stmts[j]
			for _, call := range st.calls {
				info, ok := st.sinkArgs[call]
				if !ok || !splatsMapping(info) {
					continue
				}
				st.calls = append(st.calls, kwargsSplatCall)
				st.sinkArgs[kwargsSplatCall] = info
				break
			}
		}
	}
}

func splatsMapping(info sinkArgDraft) bool {
	for _, a := range info.positionalArgs {
		if strings.HasPrefix(strings.TrimSpace(a), "**") {
			return true
		}
	}
	for k := range info.keywordArgs {
		if strings.HasPrefix(k, "**") {
			return true
		}
	}
	return false
}

var (
	tsCast      = regexp.MustCompile(`\s+as\s+[\w.<>\[\]| ]+$`)
	tsAngleCast = regexp.MustCompile(`^<[\w.<>\[\]| ]+>\s*`)
	spreadOnly  = regexp.MustCompile(`^\{\s*\.{3}\s*([\w.$]+)\s*,?\s*\}$`)
)

// wholeExpr strips what keeps every field of a value -- await, parentheses,
// TypeScript casts, a lone spread into a fresh object -- and returns the
// expression left.
func wholeExpr(expr string) string {
	e := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(expr), ";"))
	for {
		before := e
		e = strings.TrimSpace(strings.TrimPrefix(e, "await "))
		e = tsCast.ReplaceAllString(e, "")
		e = tsAngleCast.ReplaceAllString(e, "")
		if strings.HasPrefix(e, "(") && matchParen(e, 0) == len(e)-1 {
			e = strings.TrimSpace(e[1 : len(e)-1])
		}
		if m := spreadOnly.FindStringSubmatch(e); m != nil {
			e = m[1]
		}
		if e == before {
			return e
		}
	}
}

// isWholeSource reports whether a source binding is the whole request object.
func isWholeSource(lang string, src taint.Source, expr string) bool {
	if src.Call == requestBoundBodyObject {
		return true
	}
	return isWholeExpr(lang, expr)
}

// keepsWhole reports whether an assignment's value is the tainted variable v
// with every field kept.
func keepsWhole(expr, v string) bool {
	return v != "" && wholeExpr(expr) == v
}

// massAssignSlots are the sinks whose first argument is the record written
// to, not the data written: Object.assign(target, ...sources),
// repository.merge(entity, ...sources).
var massAssignSlots = map[string]bool{"Object.assign": true, "merge": true}

// massAssignmentReaches reports whether, at a mass-assignment sink, the
// tainted variable v is whole, is passed whole (not one of its fields), and
// is passed where data is written -- on a receiver that writes records.
func massAssignmentReaches(lang string, sink *taint.Sink, rawCall string, info taint.SinkArgInfo, v string, ti taintInfo) bool {
	if sink.Call == "setattr" {
		// setattr(obj, name, value): the NAME drawn from a raw request
		// mapping (whole: see itemsOfWhole) lets the client set any
		// attribute. Names from a validated model dump are its declared
		// fields.
		return ti.whole && len(info.PositionalVars) > 1 && slices.Contains(info.PositionalVars[1], v)
	}
	if !ti.whole {
		return false
	}
	key := canonicalSuffix(sink.Call)
	first := 0
	switch {
	case sink.Call == "Object.assign":
		first = 1 // Object.assign(target, ...sources)
	case lang == "javascript" && !writesRecords(rawCall):
		return false // the application's own service or another object
	case massAssignSlots[key] || massAssignSlots[sink.Call]:
		first = 1
	}
	for slot := first; slot < len(info.PositionalArgs); slot++ {
		if inlineOperandName(slot) == v || usedWhole(info.PositionalArgs[slot], v) {
			return true
		}
	}
	return false
}

// usedWhole reports whether the argument text passes v itself -- bare or
// spread -- rather than reading from it: `dto` and `...dto` are whole,
// `dto.name`, `dto["name"]` and `dto()` are not.
func usedWhole(arg, v string) bool {
	for i := 0; i+len(v) <= len(arg); {
		j := strings.Index(arg[i:], v)
		if j < 0 {
			return false
		}
		at := i + j
		end := at + len(v)
		i = end
		if at > 0 && isIdentPart(arg[at-1]) || end < len(arg) && isIdentPart(arg[end]) {
			continue // part of a longer name
		}
		if at > 0 && arg[at-1] == '.' && (at < 3 || arg[at-3:at] != "...") {
			continue // an attribute of something else
		}
		next := strings.TrimLeft(arg[end:], " \t")
		if strings.HasPrefix(next, ".") || strings.HasPrefix(next, "[") || strings.HasPrefix(next, "?.") || strings.HasPrefix(next, "(") {
			continue // a field, an index or a call on it
		}
		prev := strings.TrimRight(arg[:at], " \t")
		if strings.HasPrefix(next, ":") && (strings.HasSuffix(prev, "{") || strings.HasSuffix(prev, ",")) {
			continue // an object key named like the variable
		}
		return true
	}
	return false
}

// dataLayerReceiver names what writes records: a model class (User.create),
// a repository or model object, Prisma, a query builder or entity manager.
var dataLayerReceiver = regexp.MustCompile(`(?i)(?:repo|repository|model|collection)$|^(?:db|knex|em|manager|entitymanager|datasource|tx|trx)$`)

// writesRecords reports whether a create/update/save call is made on the data
// layer rather than on the application's own service: `this.dealsService.update`
// hands the DTO on, and the service's own write is judged where it happens.
func writesRecords(rawCall string) bool {
	segs := strings.Split(rawCall, ".")
	if len(segs) < 2 {
		return false
	}
	for _, s := range segs[:len(segs)-1] {
		if s == "prisma" {
			return true
		}
	}
	recv := segs[len(segs)-2]
	if recv == "" {
		return false
	}
	if recv[0] >= 'A' && recv[0] <= 'Z' {
		return true // a model class: User.create, Deal.findByIdAndUpdate
	}
	return dataLayerReceiver.MatchString(recv)
}

// wholeBinding decides whole-ness for a statement bound from a source: a
// field binding (destructuring, a loop target) is whole only as the keys of a
// whole mapping; any other binding when its expression is the whole object.
func wholeBinding(lang string, st *taint.Statement, src taint.Source, tainted map[string]taintInfo) bool {
	if st.FieldBinding {
		return itemsOfWhole(lang, st.Expr, tainted)
	}
	return isWholeSource(lang, src, st.Expr)
}
