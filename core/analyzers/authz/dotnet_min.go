package authz

import (
	"fmt"
	"regexp"
	"strings"
)

// Minimal APIs and endpoint route builders: see dotnet.go.

var csLambdaRe = regexp.MustCompile(`^\(?\s*(?:\w+\s+)?(\w+)\s*\)?\s*=>\s*\{`)

type csExec struct {
	ix       *csIndex
	p        *csProject
	f        *csFile
	code     string
	vars     map[string]*csRouter
	builders map[string]bool
	ret      *csRouter
	opaque   bool
	depth    int
}

func (ix *csIndex) minimalRoutes() {
	for _, d := range ix.order {
		p := ix.projects[d]
		for _, f := range p.files {
			if f.aspnet {
				e := &csExec{ix: ix, p: p, f: f, code: topLevelCode(f), vars: map[string]*csRouter{}, builders: map[string]bool{}}
				e.region(0, len(e.code))
			}
		}
		for _, fn := range p.all {
			if !fn.builder && fn.file.aspnet {
				ix.runFunc(p, fn, nil, nil, false, 0)
			}
		}
	}
	for _, d := range ix.order {
		p := ix.projects[d]
		for _, fn := range p.all {
			if !p.handled[fn] && fn.file.aspnet {
				ix.runFunc(p, fn, nil, nil, true, 0)
			}
		}
	}
}

// topLevelCode blanks every type declaration, leaving the file's top-level statements.
func topLevelCode(f *csFile) string {
	b := []byte(f.code)
	var blank func(from, to int)
	blank = func(from, to int) {
		for _, m := range csScan(f.code, from, to) {
			tm := csTypeRe.FindStringSubmatch(m.decl(f.code))
			switch {
			case tm == nil:
			case tm[1] == "namespace":
				if m.bodyStart >= 0 {
					blank(m.bodyStart+1, m.bodyEnd)
				}
			default:
				for i := m.declStartWithAttrs; i < m.end && i < len(b); i++ {
					if b[i] != '\n' {
						b[i] = ' '
					}
				}
			}
		}
	}
	blank(0, len(f.code))
	return string(b)
}

func (ix *csIndex) runFunc(p *csProject, fn *csFunc, recv *csRouter, args []*csRouter, opaque bool, depth int) *csRouter {
	key := fmt.Sprintf("%s:%d|%p", fn.file.path, fn.member.declStart, recv)
	for _, a := range args {
		key += fmt.Sprintf("|%p", a)
	}
	if r, done := p.memo[key]; done {
		return r
	}
	p.memo[key] = nil
	p.handled[fn] = true
	if depth > 8 || fn.member.bodyStart < 0 {
		return nil
	}
	e := &csExec{ix: ix, p: p, f: fn.file, code: fn.file.code, vars: map[string]*csRouter{}, builders: map[string]bool{}, opaque: opaque, depth: depth}
	k := 0
	for i, name := range fn.params {
		if name == "" || !csRouterType.MatchString(fn.types[i]) {
			continue
		}
		var r *csRouter
		switch {
		case i == 0 && recv != nil:
			r = recv
		case i-btoi(recv != nil) >= 0 && i-btoi(recv != nil) < len(args):
			r = args[i-btoi(recv != nil)]
		}
		if r == nil {
			r = &csRouter{opaque: true}
		}
		e.vars[name] = r
		k++
	}
	e.region(fn.member.bodyStart+1, fn.member.bodyEnd)
	p.memo[key] = e.ret
	return e.ret
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (e *csExec) region(from, to int) {
	for _, s := range splitStatements(e.code, from, to, false) {
		e.statement(s)
	}
}

func (e *csExec) statement(s span) {
	text := e.code[s.start:s.end]
	for _, kw := range []string{"await ", "return "} {
		if rest, ok := strings.CutPrefix(text, kw); ok {
			s.start += len(text) - len(rest)
			text = rest
			if kw == "return " {
				if r := e.chain(s); r != nil && e.ret == nil {
					e.ret = r
				}
				return
			}
		}
	}
	if m := csAssignRe.FindStringSubmatchIndex(text); m != nil {
		name := text[m[2]:m[3]]
		rhs := trimSpan(e.code, span{s.start + m[4], s.end})
		e.assign(name, rhs)
		return
	}
	e.chain(s)
	e.scanCalls(s)
}

func (e *csExec) assign(name string, rhs span) {
	text := e.code[rhs.start:rhs.end]
	if strings.HasPrefix(text, "WebApplication.CreateBuilder") || strings.HasPrefix(text, "WebApplication.CreateSlimBuilder") || strings.HasPrefix(text, "WebApplication .CreateBuilder") {
		e.builders[name] = true
		return
	}
	if r := e.chain(rhs); r != nil {
		e.vars[name] = r
		return
	}
	delete(e.vars, name)
}

// chain executes a call chain and returns the route builder it ends on.
func (e *csExec) chain(s span) *csRouter {
	segs, ok := parseChain(e.code, s)
	if !ok {
		return nil
	}
	var cur *csRouter
	i := 1
	first := segs[0]
	switch {
	case first.call:
		return nil
	case len(segs) > 1 && first.name == "WebApplication" && segs[1].call && strings.HasPrefix(segs[1].name, "Create") && !strings.Contains(segs[1].name, "Builder"):
		cur, i = &csRouter{opaque: e.opaque}, 2
	case len(segs) > 1 && e.builders[first.name] && segs[1].name == "Build":
		cur, i = &csRouter{opaque: e.opaque}, 2
	default:
		cur = e.vars[first.name]
		if cur == nil && len(segs) == 2 && segs[1].name == "UseEndpoints" {
			if args := splitArgs(e.code, segs[1].args.start, segs[1].args.end); len(args) == 1 {
				e.useEndpoints(args[0])
			}
			return nil
		}
		if cur == nil {
			return e.staticCall(segs)
		}
	}
	return e.links(cur, segs[i:])
}

// staticCall: Extensions.MapApi(app, ...) where the class is a static container.
func (e *csExec) staticCall(segs []seg) *csRouter {
	if len(segs) != 2 || !segs[1].call {
		return nil
	}
	fn := e.p.funcs[segs[1].name]
	if fn == nil || fn.dup || !fn.builder || e.depth >= 8 {
		return nil
	}
	return e.ix.runFunc(e.p, fn, nil, e.argRouters(segs[1].args), e.opaque, e.depth+1)
}

func (e *csExec) argRouters(args span) []*csRouter {
	var out []*csRouter
	for _, a := range splitArgs(e.code, args.start, args.end) {
		out = append(out, e.chain(a))
	}
	return out
}

func (e *csExec) links(cur *csRouter, segs []seg) *csRouter {
	epIdx, inEndpoint := -1, false
	ctl := false
	for _, sg := range segs {
		if !sg.call {
			return nil
		}
		args := splitArgs(e.code, sg.args.start, sg.args.end)
		switch name := sg.name; {
		case inEndpoint:
			if epIdx >= 0 {
				e.convention(&e.ix.recs[epIdx], sg)
			}
		case csMapVerbs[name] != "":
			if cur == nil {
				return nil
			}
			epIdx, inEndpoint = e.endpoint(cur, sg, args), true
		case name == "MapGroup" && len(args) >= 1:
			if cur == nil {
				return nil
			}
			cur = e.group(cur, args[0])
		case name == "MapControllers" || name == "MapDefaultControllerRoute":
			ctl = true
		case name == "RequireAuthorization" && ctl:
			e.p.ctlGuard = true
		case name == "RequireAuthorization" && cur != nil && cur.parent != nil:
			cur.ev.authn = firstNonEmpty(cur.ev.authn, ".RequireAuthorization()")
		case name == "AllowAnonymous" && cur != nil && cur.parent != nil:
			cur.ev.public = true
		case name == "UseEndpoints" && len(args) == 1:
			e.useEndpoints(args[0])
		default:
			cur = e.extension(cur, sg)
		}
	}
	return cur
}

// extension runs a project method that takes the builder as its `this` parameter.
func (e *csExec) extension(cur *csRouter, sg seg) *csRouter {
	fn := e.p.funcs[sg.name]
	if cur == nil || fn == nil || fn.dup || !fn.builder || e.depth >= 8 {
		return cur
	}
	if r := e.ix.runFunc(e.p, fn, cur, e.argRouters(sg.args), e.opaque, e.depth+1); r != nil {
		return r
	}
	return cur
}

func (e *csExec) group(parent *csRouter, arg span) *csRouter {
	g := &csRouter{parent: parent}
	if v, ok := strictLiteral(e.f.raw, e.code, trimSpan(e.code, arg)); ok {
		g.prefix = v
	} else {
		g.opaque = true
	}
	return g
}

func (e *csExec) useEndpoints(arg span) {
	text := e.code[arg.start:arg.end]
	m := csLambdaRe.FindStringSubmatch(text)
	if m == nil {
		return
	}
	open := arg.start + strings.IndexByte(text, '{')
	end := matchClose(e.code, open)
	if end < 0 {
		return
	}
	sub := &csExec{ix: e.ix, p: e.p, f: e.f, code: e.code, vars: map[string]*csRouter{m[1]: {opaque: e.opaque}}, builders: map[string]bool{}, opaque: e.opaque, depth: e.depth}
	sub.region(open+1, end)
}

// endpoint records a Map* call and returns its index in the table, or -1 when
// its path was not a literal and nothing was recorded.
func (e *csExec) endpoint(rt *csRouter, sg seg, args []span) int {
	if len(args) < 2 {
		return -1
	}
	rel, ok := strictLiteral(e.f.raw, e.code, trimSpan(e.code, args[0]))
	if !ok {
		return -1
	}
	method := csMapVerbs[sg.name]
	if sg.name == "MapMethods" {
		method = "ALL"
		if len(args) >= 3 {
			var ms []string
			for _, m := range regexp.MustCompile(`"([A-Za-z]+)"`).FindAllStringSubmatch(string(e.f.raw[args[1].start:args[1].end]), -1) {
				ms = append(ms, strings.ToUpper(m[1]))
			}
			if len(ms) == 1 {
				method = ms[0]
			}
		}
	}
	h := args[len(args)-1]
	rec := csRec{rt: rt, method: method, rel: rel, file: e.f, project: e.p, line: lineAt(e.f.lineStarts, sg.start), ev: e.handlerEvidence(h)}
	e.ix.recs = append(e.ix.recs, rec)
	return len(e.ix.recs) - 1
}

// handlerEvidence reads the delegate passed to MapGet: attributes on a lambda,
// the attributes and body of a method group, or a read of the caller.
func (e *csExec) handlerEvidence(h span) csEvidence {
	var ev csEvidence
	text := e.f.sans[h.start:h.end]
	for _, m := range csHandlerAttrRe.FindAllStringSubmatch(text, -1) {
		if m[1] == "AllowAnonymous" {
			ev.public = true
		} else {
			ev.authn = firstNonEmpty(ev.authn, "[Authorize]")
		}
	}
	if segs, ok := parseChain(e.code, trimSpan(e.code, h)); ok && !segs[len(segs)-1].call {
		if fn := e.p.funcs[segs[len(segs)-1].name]; fn != nil && !fn.dup {
			for _, a := range fn.member.attrs {
				ev.merge(csAttrEvidence(fn.file, a))
			}
			text = fn.file.sans[fn.member.declStart:fn.member.end]
		}
	}
	if ev.authn == "" && !ev.public && csInlineAuthRe.MatchString(text) {
		ev.authn = inlineAuthLabel
	}
	return ev
}

// convention applies .RequireAuthorization() and .AllowAnonymous() to the endpoint just mapped.
func (e *csExec) convention(rec *csRec, sg seg) {
	switch sg.name {
	case "RequireAuthorization":
		rec.ev.authn = firstNonEmpty(rec.ev.authn, ".RequireAuthorization()")
	case "AllowAnonymous":
		rec.ev.public = true
	}
}

// scanCalls runs static extension calls such as Api.Map(app) found inside a statement.
func (e *csExec) scanCalls(s span) {
	for _, c := range findCalls(e.code, s) {
		_, name, found := strings.Cut(c.callee, ".")
		if !found || strings.Contains(name, ".") {
			continue
		}
		fn := e.p.funcs[name]
		if fn == nil || fn.dup || !fn.builder || e.depth >= 8 {
			continue
		}
		if len(fn.types) > 0 && strings.HasPrefix(strings.TrimSpace(fn.types[0]), "this ") {
			continue
		}
		args := e.argRouters(c.args)
		if len(args) > 0 && args[0] != nil {
			e.ix.runFunc(e.p, fn, nil, args, e.opaque, e.depth+1)
		}
	}
}

// routes assembles the route table: controllers first, then minimal APIs.
func (ix *csIndex) routes() ([]Route, []routeView) {
	ix.minimalRoutes()
	ix.controllerRoutes()
	seen := map[string]bool{}
	for _, rec := range ix.recs {
		inh, opaque := rec.rt.inherited()
		ev := rec.ev
		ev.merge(inh)
		p := goJoin(rec.rt.fullPrefix(), rec.rel)
		key := rec.file.path + ":" + fmt.Sprint(rec.line) + " " + rec.method + " " + p
		if seen[key] {
			continue
		}
		seen[key] = true
		rt := Route{Method: rec.method, Path: p, FilePath: rec.file.path, Line: rec.line, Authn: ev.authn, Authz: ev.authz, Reader: ReaderASPNET}
		ix.out = append(ix.out, rt)
		ix.views = append(ix.views, routeView{route: rt, guardUnseen: (opaque || rec.project.guarded) && !ev.public, declaredPublic: ev.public, framework: "aspnet"})
	}
	return ix.out, ix.views
}
