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
// tainted variable v is whole and passed where data is written.
func massAssignmentReaches(sink *taint.Sink, info taint.SinkArgInfo, v string, ti taintInfo) bool {
	if !ti.whole {
		return false
	}
	if !massAssignSlots[canonicalSuffix(sink.Call)] && !massAssignSlots[sink.Call] {
		return true
	}
	for slot := 1; slot < len(info.PositionalVars); slot++ {
		for _, pv := range info.PositionalVars[slot] {
			if pv == v {
				return true
			}
		}
	}
	for slot := 1; slot < len(info.PositionalArgs); slot++ {
		if inlineOperandName(slot) == v {
			return true
		}
	}
	return false
}
