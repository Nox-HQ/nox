package authz

import (
	"strings"
)

// gorilla/mux routes, read by the Go reader's interpreter (golang.go).
//
// A mux route is a chain on a router: `r.HandleFunc("/x", h).Methods("POST")`,
// `r.Handle("/x", h)`, or the builder form `r.Methods("GET").Path("/x").
// HandlerFunc(h)`. A subrouter is `r.PathPrefix("/api").Subrouter()`, whose
// routes are served under the prefix.
//
// What it states, and no more:
//
//   - the receiver must trace to a router built from the gorilla/mux package
//     (mux.NewRouter, a *mux.Router parameter bound by a caller in the scanned
//     tree): HandleFunc on any other value is not a registration;
//   - Methods narrows the route to the verbs it lists, each a literal; with no
//     Methods the route answers every method (ALL). A Methods argument that is
//     not a literal makes the route unreadable, so it is skipped, not guessed;
//   - `Use(mw)` is judged like the other routers' middleware, with one
//     difference that is the router's own: mux applies it when a request
//     matches one of the router's routes, so it covers routes written before
//     the Use as well, and a parent's Use covers its subrouters.
//
// Not read: a Methods call on a router followed by Subrouter, matchers other
// than Path and PathPrefix (Host, Headers, Queries) as route identity, and
// routes whose path is a constant or a concatenation.

var muxIgnoredMatchers = setOf("Host", "Headers", "HeadersRegexp", "Queries", "Schemes", "Name", "MatcherFunc", "BuildOnly", "Methods")

// muxStarters are the calls that begin a route on a router.
var muxStarters = setOf("HandleFunc", "Handle", "Path", "Methods")

// muxSubrouter evaluates `PathPrefix("/p")[.Methods(..)...].Subrouter()` starting at
// idx, returning the subrouter and the index of the Subrouter link. A PathPrefix
// that does not end in Subrouter is not a router: the result is nil.
func (e *goExec) muxSubrouter(r *goRouter, segs []seg, idx int) (*goRouter, int) {
	args := splitArgs(e.file.code, segs[idx].args.start, segs[idx].args.end)
	j := idx + 1
	for j < len(segs) && segs[j].call && segs[j].name != "Subrouter" && muxIgnoredMatchers[segs[j].name] {
		j++
	}
	if len(args) == 0 || j >= len(segs) || !segs[j].call || segs[j].name != "Subrouter" {
		return nil, len(segs)
	}
	p, ok := e.literal(args[0])
	return &goRouter{kind: goMux, root: r.root, parent: r, prefix: p, opaque: r.opaque || !ok}, j
}

// muxChain reads a statement that registers a mux route. It reports false when
// the receiver is not a gorilla/mux router, so every other reader still sees
// the statement.
func (e *goExec) muxChain(segs []seg) bool {
	start := -1
	for i := 1; i < len(segs); i++ {
		if segs[i].call && muxStarters[segs[i].name] {
			start = i
			break
		}
	}
	if start < 0 {
		return false
	}
	for _, sg := range segs[start:] {
		if sg.name == "Subrouter" {
			return false
		}
	}
	rt := e.evalSegs(segs[:start])
	if rt == nil || rt.kind != goMux {
		return false
	}
	var (
		path       *span
		verbs      []string
		handlers   goHandlers
		haveTarget bool
		readable   = true
	)
	for _, sg := range segs[start:] {
		if !sg.call {
			continue
		}
		args := splitArgs(e.file.code, sg.args.start, sg.args.end)
		switch sg.name {
		case "HandleFunc", "Handle":
			if len(args) < 2 {
				return true
			}
			path, handlers, haveTarget = &args[0], goHandlers{handler: args[1:2]}, true
		case "Path":
			if len(args) == 1 {
				path = &args[0]
			}
		case "HandlerFunc", "Handler":
			if len(args) == 1 {
				handlers, haveTarget = goHandlers{handler: args}, true
			}
		case "Methods":
			for _, a := range args {
				v, ok := e.literal(a)
				if _, verb := goVerbs[strings.ToUpper(v)]; !ok || !verb {
					readable = false
					continue
				}
				verbs = append(verbs, strings.ToUpper(v))
			}
		}
	}
	if path == nil || !haveTarget || !readable {
		return true // a mux registration this reader cannot read: listed by no one, claimed by no one
	}
	pat, ok := e.literal(*path)
	if !ok {
		return true
	}
	if len(verbs) == 0 {
		verbs = []string{"ALL"}
	}
	line := lineAt(e.file.lineStarts, segs[start].start)
	for _, v := range verbs {
		e.record(rt, v, pat, line, handlers)
	}
	return true
}
