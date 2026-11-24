package engine

import (
	"regexp"
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
	return wholeObjectSources[lang][wholeExpr(expr)]
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
func massAssignmentReaches(sink *taint.Sink, rawCall string, info taint.SinkArgInfo, v string, ti taintInfo) bool {
	if !ti.whole {
		return false
	}
	key := canonicalSuffix(sink.Call)
	first := 0
	switch {
	case sink.Call == "Object.assign":
		first = 1 // Object.assign(target, ...sources)
	case !writesRecords(rawCall):
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
