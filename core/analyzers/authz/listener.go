package authz

import (
	"net"
	"regexp"
	"strings"
)

// Loopback listeners.
//
// A Go router that the program serves only on a loopback address (the
// `net/http/pprof` mux on "localhost:6060" is the usual one) is reachable by
// processes on the same host and by no one else, so "no authentication in
// front of it" is not an exposure of it: the network boundary is the control.
//
// What it states, and no more: a router is loopback-only when every place the
// reader sees it served names a literal loopback host (localhost, 127.0.0.0/8,
// ::1). One serve on any other address (a wildcard such as ":6060" or
// "0.0.0.0:6060", an address read from configuration, a host the reader cannot
// read) makes it exposed, and so does a router that is never seen served, since
// then nothing says where it listens. The address is only read where it is
// written next to the router: `http.ListenAndServe(addr, mux)` and an
// `http.Server{Addr: addr, Handler: mux}` literal.

var (
	goListenServeRe = regexp.MustCompile(`\bListenAndServe(?:TLS)?\s*\(`)
	goServerTypeRe  = regexp.MustCompile(`\bhttp\s*\.\s*Server\s*$`)
)

// isLoopbackAddr reports whether a host:port listen address binds only the
// loopback interface. An empty host (":6060") listens on every interface.
func isLoopbackAddr(addr string) bool {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// bindListeners reads the serve calls and server literals in a statement and
// records on each router's root where it is served.
func (e *goExec) bindListeners(s span) {
	code := e.file.code
	text := code[s.start:s.end]
	for _, loc := range goListenServeRe.FindAllStringIndex(text, -1) {
		open := s.start + loc[1] - 1
		c := matchClose(code, open)
		if c < 0 {
			continue
		}
		args := splitArgs(code, open+1, c)
		if len(args) < 2 {
			continue // srv.ListenAndServe(): the server literal says where
		}
		e.bindServe(args[0], args[len(args)-1])
	}
	// The statement splitter ends a statement at `{`, so a server literal is
	// the statement that ends in the type name and the brace that follows it.
	if goServerTypeRe.MatchString(text) && s.end < len(code) && code[s.end] == '{' {
		e.bindServerLiteral(s.end)
	}
}

// bindServerLiteral reads `http.Server{Addr: ..., Handler: ...}` whose brace is
// at open.
func (e *goExec) bindServerLiteral(open int) {
	code := e.file.code
	c := matchClose(code, open)
	if c < 0 {
		return
	}
	var addr, handler span
	for _, el := range splitArgs(code, open+1, c) {
		key, _, ok := strings.Cut(code[el.start:el.end], ":")
		if !ok {
			continue
		}
		v := trimSpan(code, span{el.start + len(key) + 1, el.end})
		switch strings.TrimSpace(key) {
		case "Addr":
			addr = v
		case "Handler":
			handler = v
		}
	}
	if handler.end > handler.start {
		e.bindServe(addr, handler)
	}
}

// bindServe records one serve of the router the handler expression denotes. An
// address that is missing or not a plain string literal counts as exposed.
func (e *goExec) bindServe(addr, handler span) {
	r := e.eval(handler)
	if r == nil {
		return
	}
	if addr.end > addr.start {
		if v, ok := e.literal(addr); ok && isLoopbackAddr(v) {
			r.root.loopback = true
			return
		}
	}
	r.root.exposed = true
}
