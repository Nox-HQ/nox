package authz

import (
	"regexp"
	"strings"
)

// DRF @action routes.
//
// A router registers a viewset's standard list and detail routes, and also one
// route per method decorated with `@action(detail=..., methods=[...],
// url_path=...)`: `/orders/:pk/cancel` for a detail action, `/orders/export`
// for a list action. They are routes in their own right and the easiest place
// in a viewset for a mutating endpoint to lose the class's permissions, because
// an action can override `permission_classes` and `authentication_classes`
// for itself.
//
// What this reader states: the action's path (url_path, else the function
// name), its methods (default GET), and its access control: the action's own
// `permission_classes` when it names them, the viewset's otherwise; an action
// whose `permission_classes` is AllowAny or empty, or whose
// `authentication_classes` is empty, is declared public. An action whose detail
// flag is not a literal is not read.
var (
	djActionRe        = regexp.MustCompile(`(?m)^([ \t]+)@action\s*\(`)
	djActionDetailRe  = regexp.MustCompile(`\bdetail\s*=\s*(True|False)\b`)
	djActionMethodsRe = regexp.MustCompile(`\bmethods\s*=\s*[\[(]([^\])]*)[\])]`)
	djActionURLPathRe = regexp.MustCompile(`\burl_path\s*=\s*['"]([^'"]*)['"]`)
	djActionDefRe     = regexp.MustCompile(`^(?:async[ \t]+)?def[ \t]+([A-Za-z_]\w*)`)
)

// blankActionArgs replaces the argument text of every @action(...) in text with
// spaces, offsets kept.
func blankActionArgs(text string) string {
	locs := djActionAnyRe.FindAllStringIndex(text, -1)
	if len(locs) == 0 {
		return text
	}
	b := []byte(text)
	for _, l := range locs {
		open := l[1] - 1
		end := matchClose(text, open)
		if end < 0 {
			continue
		}
		for i := open + 1; i < end; i++ {
			if b[i] != '\n' {
				b[i] = ' '
			}
		}
	}
	return string(b)
}

var djActionAnyRe = regexp.MustCompile(`@action\s*\(`)

type djAction struct {
	name    string
	detail  bool
	urlPath string
	methods []string
	args    string // the decorator's arguments, comment-free
	off     int    // of the @action
	file    *pyFile
	text    string // the function, signature and body
}

// actionsOf returns the @action methods of the viewset v and of the classes it
// derives from in the repository, nearest definition first.
func (d *djIndex) actionsOf(v djView) []djAction {
	var out []djAction
	seen := map[string]bool{}
	for _, c := range d.classChain(v) {
		if c.bodyEnd <= c.bodyStart || c.bodyEnd > len(c.file.code) {
			continue
		}
		region := c.file.code[c.bodyStart:c.bodyEnd]
		for _, m := range djActionRe.FindAllStringSubmatchIndex(region, -1) {
			if a, ok := readAction(c.file, c.bodyStart+m[3], c.bodyStart+m[1]-1, len(c.file.code)); ok && !seen[a.name] {
				seen[a.name] = true
				out = append(out, a)
			}
		}
	}
	return out
}

// readAction reads the action whose decorator argument list opens at open.
func readAction(f *pyFile, indent, open, limit int) (djAction, bool) {
	cl := matchClose(f.code, open)
	if cl < 0 {
		return djAction{}, false
	}
	a := djAction{args: f.sans[open+1 : cl], off: open, file: f}
	dm := djActionDetailRe.FindStringSubmatch(a.args)
	if dm == nil {
		return djAction{}, false
	}
	a.detail = dm[1] == "True"
	// The function: skip any further decorators.
	pos := cl + 1
	for pos < limit {
		for pos < limit && isSpace(f.code[pos]) {
			pos++
		}
		if pos < limit && f.code[pos] == '@' {
			end := pos
			for end < limit && f.code[end] != '(' && f.code[end] != '\n' {
				end++
			}
			if end < limit && f.code[end] == '(' {
				c := matchClose(f.code, end)
				if c < 0 {
					return djAction{}, false
				}
				end = c
			}
			pos = end + 1
			continue
		}
		break
	}
	nm := djActionDefRe.FindStringSubmatch(f.code[pos:min(limit, pos+200)])
	if nm == nil {
		return djAction{}, false
	}
	a.name = nm[1]
	a.urlPath = a.name
	if um := djActionURLPathRe.FindStringSubmatch(a.args); um != nil {
		a.urlPath = um[1]
	}
	a.methods = []string{"GET"}
	if mm := djActionMethodsRe.FindStringSubmatch(a.args); mm != nil {
		a.methods = nil
		for _, q := range djQuoted.FindAllStringSubmatch(mm[1], -1) {
			if mth := strings.ToUpper(q[1]); mth != "" {
				a.methods = append(a.methods, mth)
			}
		}
		if len(a.methods) == 0 {
			return djAction{}, false
		}
	}
	a.text = f.sans[pos:djBlockEnd(f, pos, indentWidth(f.code, indent))]
	return a, true
}

// indentWidth is the width of the indentation that ends just before offset at,
// that is the run of spaces and tabs the decorator line begins with.
func indentWidth(code string, at int) int {
	start := at
	for start > 0 && code[start-1] != '\n' {
		start--
	}
	return at - start
}

// djBlockEnd is the end of the function that starts at pos: the next
// non-blank line indented no deeper than the decorator, other than a line that
// only closes the signature.
func djBlockEnd(f *pyFile, pos, decoIndent int) int {
	i := strings.IndexByte(f.code[pos:], '\n')
	if i < 0 {
		return len(f.code)
	}
	for at := pos + i + 1; at < len(f.code); {
		eol := strings.IndexByte(f.code[at:], '\n')
		lineEnd := len(f.code)
		if eol >= 0 {
			lineEnd = at + eol
		}
		line := f.code[at:lineEnd]
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed != "" && len(line)-len(trimmed) <= decoIndent && !strings.HasPrefix(trimmed, ")") {
			return at
		}
		if eol < 0 {
			break
		}
		at = lineEnd + 1
	}
	return len(f.code)
}

// emitActions adds the routes of v's @action methods, under the viewset's list
// path (full + the registration's prefix).
func (d *djIndex) emitActions(v djView, list, detail string, out *[]Route, views *[]routeView) {
	for _, a := range d.actionsOf(v) {
		base := list
		if a.detail {
			base = detail
		}
		p := djJoin(base, a.urlPath)
		line := lineAt(a.file.lineStarts, a.off)
		for _, m := range a.methods {
			authn, authz, public := d.access(v, m)
			if perm := djPermClassesKwarg.FindStringSubmatch(a.args); perm != nil {
				var pub bool
				authn, authz, pub = classifyPermClasses(perm[1], m)
				public = pub
			}
			if djAuthClsEmptyKwarg.MatchString(a.args) {
				authn, authz, public = "", "", true
			}
			if public {
				authn, authz = "", ""
			} else if authn == "" && authz == "" && pyInlineAuthRe.MatchString(a.text) {
				authn = inlineAuthLabel
			}
			rt := Route{Method: m, Path: p, FilePath: a.file.path, Line: line, Authn: authn, Authz: authz, Reader: ReaderDjango}
			*out = append(*out, rt)
			*views = append(*views, routeView{route: rt, handler: a.text, known: true, chain: v.decos + " " + v.bases + " " + a.args,
				guardUnseen: d.guard, declaredPublic: public, framework: "django"})
		}
	}
}

var (
	djPermClassesKwarg  = regexp.MustCompile(`\bpermission_classes\s*=\s*[\[(]([^\])]*)[\])]`)
	djAuthClsEmptyKwarg = regexp.MustCompile(`\bauthentication_classes\s*=\s*[\[(]\s*[\])]`)
)
