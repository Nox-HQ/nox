package engine

import (
	"regexp"
	"strings"
)

// Handler parameters that JavaScript and Python web frameworks bind from the
// request, seeded from the same sentinels as the JVM annotations (see
// annotated_params.go). The parameter's name is arbitrary, so only what binds
// it marks it: a NestJS decorator, or a Python route decorator on the function.

// nestRequestDecorators maps a NestJS parameter decorator to the part of the
// request it binds. Kept apart from requestBindingAnnotations: in Java,
// MyBatis's @Param names a mapper argument, not request data.
var nestRequestDecorators = map[string]string{
	"Body":          requestBoundBody,
	"Query":         requestBoundQuery,
	"Param":         requestBoundQuery,
	"Headers":       requestBoundHeader,
	"Ip":            requestBoundHeader,
	"HostParam":     requestBoundHeader,
	"UploadedFile":  requestBoundBody,
	"UploadedFiles": requestBoundBody,
}

// nestRequestBound returns the request-bound parameters of a JavaScript or
// TypeScript method header: `run(@Body("cmd") cmd: string, @Req() req)` gives
// cmd -> RequestBoundBody. Nil when the header carries no such decorator.
func nestRequestBound(header string) map[string]string {
	if !strings.Contains(header, "@") {
		return nil
	}
	inner := headerParamList(header)
	if inner == "" {
		return nil
	}
	var out map[string]string
	for _, slot := range splitTopLevelArgs(inner) {
		anns, rest := leadingAnnotations(slot)
		kind := ""
		for _, a := range anns {
			if k, ok := nestRequestDecorators[a]; ok {
				kind = k
				break
			}
		}
		if kind == "" {
			continue
		}
		if name := tsParamName(rest); isSimpleIdent(name) {
			if out == nil {
				out = map[string]string{}
			}
			out[name] = kind
		}
	}
	return out
}

// tsParamName is the declared name of a TypeScript parameter slot with its
// decorators removed: `readonly cmd?: string = ""` gives cmd.
func tsParamName(slot string) string {
	s := strings.TrimSpace(slot)
	for _, mod := range []string{"public ", "private ", "protected ", "readonly "} {
		s = strings.TrimPrefix(s, mod)
	}
	if i := strings.IndexAny(s, ":?= "); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// pyRouteDecorator matches a decorator that registers the function as an HTTP
// route: `@app.get(...)`, `@router.post(...)`, `@bp.route(...)`,
// `@app.api_route(...)`. FastAPI binds every parameter of such a function from
// the path, query or body; Flask binds every parameter from the URL's
// variables. Either way the parameter holds what the client sent.
var pyRouteDecorator = regexp.MustCompile(`^@\s*[A-Za-z_][\w.]*\.(?:get|post|put|patch|delete|head|options|route|api_route)\s*\(`)

// pyInjectedTypes are parameter annotations a framework fills with its own
// objects, not request values: they are read through their attributes, which
// the catalog's source chains already cover (request.query_params, ...).
var pyInjectedTypes = map[string]bool{
	"Request": true, "Response": true, "BackgroundTasks": true, "WebSocket": true,
	"HTTPConnection": true, "Session": true, "AsyncSession": true, "SecurityScopes": true,
	"HttpRequest": true,
}

// pyRequestBound returns the request-bound parameters of a Python route
// function, given its header and the decorators directly above it. A
// parameter filled by dependency injection (`= Depends(...)`, `= Security(...)`,
// `Annotated[..., Depends(...)]`), typed as a framework object, or named self
// or cls is not one.
func pyRequestBound(header string, decorators []string) map[string]string {
	route := false
	for _, d := range decorators {
		if pyRouteDecorator.MatchString(d) {
			route = true
			break
		}
	}
	if !route {
		return nil
	}
	inner := headerParamList(header)
	var out map[string]string
	for _, slot := range splitTopLevelArgs(inner) {
		slot = strings.TrimSpace(slot)
		if slot == "" || strings.HasPrefix(slot, "*") || slot == "/" {
			continue
		}
		if strings.Contains(slot, "Depends(") || strings.Contains(slot, "Security(") {
			continue
		}
		name, annotation := slot, ""
		if i := strings.IndexAny(slot, ":="); i >= 0 {
			name = strings.TrimSpace(slot[:i])
			if slot[i] == ':' {
				annotation = slot[i+1:]
				if j := strings.Index(annotation, "="); j >= 0 {
					annotation = annotation[:j]
				}
			}
		}
		annotation = strings.TrimSpace(annotation)
		if name == "self" || name == "cls" || !isSimpleIdent(name) {
			continue
		}
		base := annotation
		if i := strings.LastIndexByte(base, '.'); i >= 0 {
			base = base[i+1:]
		}
		if pyInjectedTypes[base] {
			continue
		}
		kind := requestBoundQuery
		if annotation != "" && annotation[0] >= 'A' && annotation[0] <= 'Z' && !strings.HasPrefix(annotation, "Optional") &&
			!strings.HasPrefix(annotation, "List") && !strings.HasPrefix(annotation, "Annotated") {
			kind = requestBoundBody // a model class: FastAPI reads it from the body
		}
		if out == nil {
			out = map[string]string{}
		}
		out[name] = kind
	}
	return out
}

// useServerDirective reports a line that is the "use server" directive alone.
func useServerDirective(raw string) bool {
	t := strings.TrimRight(strings.TrimSpace(raw), ";")
	return t == `"use server"` || t == `'use server'`
}

// serverActionParams marks every parameter of a Next.js server action as a
// request value: the client invokes the action with arguments it chooses,
// usually a FormData. Kept alongside any decorator binding already there.
func serverActionParams(u *unitDraft) {
	for _, p := range u.params {
		if !isSimpleIdent(p) {
			continue
		}
		if u.requestBound == nil {
			u.requestBound = map[string]string{}
		}
		if _, set := u.requestBound[p]; !set {
			u.requestBound[p] = requestBoundBody
		}
	}
}
