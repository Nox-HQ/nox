// Package errleak reports exception detail written into an HTTP response
// (CWE-209) in JavaScript/TypeScript, Python and Java.
//
// THE PROPOSITION. ERRLEAK-001 claims:
//
//	Inside an exception handler -- a catch block, a promise .catch, an Express
//	error middleware, a Python except block or Flask errorhandler, a Spring
//	@ExceptionHandler -- the caught exception's detail is written into the
//	response sent to the client: its stack trace, the whole exception object,
//	its string form, a formatted traceback, or (for an exception of a generic
//	type) its message.
//
// An exception raised by a database driver, a parser or the runtime carries
// what the client must not see: SQL text, table and column names, file
// paths, internal host names, library versions, the shape of the code. A
// stack trace carries all of it.
//
// WHAT COUNTS AS THE RESPONSE. A call that writes one: Express
// res.send/json/end/write/render, Fastify reply.send, Koa ctx.body,
// Next.js/Fetch Response, NestJS HttpException; Flask/Django/FastAPI
// jsonify, Response, HttpResponse, JsonResponse, render_template, abort,
// HTTPException; Spring ResponseEntity, the servlet writer, a model or flash
// attribute, Struts action errors, sendError. A `return` counts where the
// function's return value is the response: a Python view or error handler,
// a Spring @ExceptionHandler or controller method.
//
// WHAT IS NOT REPORTED. A message (e.message, getMessage(), str(e)) of an
// exception of a specific type -- a validation error, a not-found, a value
// error -- is usually written for the user, and is not reported; nor is one
// inside a JavaScript catch block that tells error kinds apart (instanceof,
// err.name/err.code checks): there the developer chose what to send. A
// stack trace, the whole object or a traceback is reported regardless of
// type. A log call is not a response (that is CWE-532, another claim).
package errleak

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/rules"
	"github.com/nox-hq/nox/core/source"
)

// RuleID is ERRLEAK-001.
const RuleID = "ERRLEAK-001"

// Analyzer reports exception detail written into HTTP responses.
type Analyzer struct{}

// NewAnalyzer constructs the analyzer.
func NewAnalyzer() *Analyzer { return &Analyzer{} }

// Rules returns the rule this analyzer can emit, for the rule catalogue.
func (a *Analyzer) Rules() *rules.RuleSet {
	rs := rules.NewRuleSet()
	rs.Add(&rules.Rule{
		ID:          RuleID,
		Version:     "1.0",
		Description: "Exception detail written into the HTTP response: a caught exception's stack trace, object, string form or traceback, or the message of an exception of a generic type, sent to the client (CWE-209)",
		Severity:    findings.SeverityLow,
		// Medium: the handler, the response call and the exception's use in
		// it are read from the source; whether the message of a generic
		// exception holds anything sensitive depends on what raised it.
		Confidence: findings.ConfidenceMedium,
		Tags:       []string{"error-handling", "information-exposure", "cwe-209", "owasp-a05"},
		Remediation: "Send the client a fixed message and a correlation id, and write the exception (with its stack) to the server log under that id: " +
			"Express `res.status(500).json({ error: \"Internal error\", id })` and `logger.error({ err, id })`; " +
			"Flask/Django `return jsonify(error=\"Internal error\", id=id), 500` with `logger.exception(...)`; " +
			"Spring a @ControllerAdvice that returns a ProblemDetail without the exception's message. " +
			"Messages written for the user belong to exceptions of your own types; send only those.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/209.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html",
		},
		Metadata: map[string]string{"cwe": "CWE-209"},
	})
	return rs
}

var (
	jsExts = map[string]bool{".js": true, ".mjs": true, ".cjs": true, ".jsx": true, ".ts": true, ".mts": true, ".cts": true, ".tsx": true}
)

// ScanArtifacts reports exception detail written into responses.
func (a *Analyzer) ScanArtifacts(ctx context.Context, artifacts []discovery.Artifact) (*findings.FindingSet, error) {
	fs := findings.NewFindingSet()
	for _, art := range artifacts {
		if err := ctx.Err(); err != nil {
			return fs, err
		}
		ext := strings.ToLower(filepath.Ext(art.Path))
		var lang lexctx.Lang
		switch {
		case jsExts[ext] && !strings.HasSuffix(art.Path, ".d.ts"):
			lang = lexctx.LangJavaScript
		case ext == ".py":
			lang = lexctx.LangPython
		case ext == ".java":
			lang = lexctx.LangJava
		default:
			continue
		}
		if source.IsTestPath(art.Path) {
			continue
		}
		content, err := os.ReadFile(art.AbsPath)
		if err != nil || source.IsGenerated(content) {
			continue
		}
		for _, f := range ScanFile(art.Path, lang, content) {
			fs.Add(f)
		}
	}
	return fs, nil
}

// ScanFile returns the findings in one source file.
func ScanFile(path string, lang lexctx.Lang, content []byte) []findings.Finding {
	if !mayHandle.Match(content) {
		return nil
	}
	v := newView(lang, content)
	var hits []hit
	switch lang {
	case lexctx.LangJavaScript:
		hits = scanJS(v)
	case lexctx.LangPython:
		hits = scanPython(v)
	case lexctx.LangJava:
		hits = scanJava(v)
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].at < hits[j].at })
	var out []findings.Finding
	seen := map[int]bool{}
	for _, h := range hits {
		line := lexctx.LineForOffset(content, h.at)
		if seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, findings.Finding{
			RuleID:     RuleID,
			Severity:   findings.SeverityLow,
			Confidence: findings.ConfidenceMedium,
			Message:    "Exception detail written into the HTTP response: " + h.what + " of the caught exception reaches the client (CWE-209)",
			Location:   findings.Location{FilePath: path, StartLine: line, EndLine: line},
			Metadata:   map[string]string{"cwe": "CWE-209", "language": lang.String()},
		})
	}
	return out
}

// mayHandle is a cheap prefilter: a file without an exception handler cannot
// match.
var mayHandle = regexp.MustCompile(`catch|except|ExceptionHandler|errorhandler|exception_handler|\(\s*(?:err|error|e|ex|exc)\s*(?::[^,)]*)?,`)

// view is one file two ways, offsets kept: code has strings and comments
// blanked (for structure: brackets, keywords, indentation); text has only
// comments blanked (for what a response carries: a template literal or an
// f-string holds the exception inside a string).
type view struct {
	lang lexctx.Lang
	code string
	text string
}

func newView(lang lexctx.Lang, content []byte) view {
	code := []byte(string(content))
	text := []byte(string(content))
	for _, r := range lexctx.Classify(lang, content) {
		if r.Kind == lexctx.KindCode {
			continue
		}
		for i := r.Start; i < r.End && i < len(code); i++ {
			if code[i] == '\n' {
				continue
			}
			code[i] = ' '
			if r.Kind == lexctx.KindComment {
				text[i] = ' '
			}
		}
	}
	return view{lang: lang, code: string(code), text: string(text)}
}

// handler is one exception handler: the names the exception is bound to,
// whether its type is generic, where its body is, and whether a return in it
// is the response.
type handler struct {
	// vars maps each name the exception is bound to (and each alias made
	// from it) to the strongest exposure it can carry: the exception itself
	// carries everything, `msg = e.getMessage()` only a message.
	vars    map[string]int
	generic bool
	start   int
	end     int
	returns bool
	// bound and fnEnd (Python): the names the except clause bound, and where
	// the enclosing function ends, for aliases used after the block.
	bound map[string]bool
	fnEnd int
}

type hit struct {
	at   int
	what string
}

// exposure classes, strongest first.
const (
	exNone = iota
	exMessage
	exDetail
)

// classify reports how args expose any of vars, and what, given the
// language's patterns. A name's exposure is capped by what it carries.
func classify(args string, vars map[string]int, pats []exposurePattern) (best int, what string) {
	for v, limit := range vars {
		for _, p := range pats {
			c := min(p.class, limit)
			if c > best && p.compile(v).MatchString(args) {
				best, what = c, p.what
				if limit < p.class {
					what = "the message"
				}
			}
		}
	}
	return best, what
}

// exposurePattern is one way to write an exception's detail, with VAR
// standing for the bound name.
type exposurePattern struct {
	re    string
	class int
	what  string
}

// rebindRe is a right-hand side that is only another name, perhaps cast.
var rebindRe = regexp.MustCompile(`^\(?\s*([A-Za-z_$][\w$]*)\s*(?:as\s+[\w.$<>|\s]+)?\)?\s*;?\s*$`)

var patternCache sync.Map // pattern + "\x00" + name -> *regexp.Regexp

func (p exposurePattern) compile(v string) *regexp.Regexp {
	key := p.re + "\x00" + v
	if re, ok := patternCache.Load(key); ok {
		return re.(*regexp.Regexp)
	}
	// The name, or the name under a TypeScript cast: `(err as Error).stack`.
	q := regexp.QuoteMeta(v)
	bound := `(?:\b` + q + `\b|\(\s*` + q + `\s+as\s+[\w.$<>|\s]+\))`
	re := regexp.MustCompile(strings.ReplaceAll(strings.ReplaceAll(p.re, `\bVAR`, bound), "VAR", bound))
	patternCache.Store(key, re)
	return re
}

// matchClose returns the index of the bracket closing the one at open.
func matchClose(s string, open int, o, c byte) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case o:
			depth++
		case c:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// withAliases adds to h.vars the names assigned from an exposure of them
// inside body (`const msg = err.message`, `String detail = e.getMessage();`,
// `error = f"failed: {e}"`), each carrying what its right-hand side carries.
// One pass, in source order.
func (h *handler) withAliases(body string, assign *regexp.Regexp, pats []exposurePattern) {
	for _, m := range assign.FindAllStringSubmatch(body, -1) {
		if _, bound := h.vars[m[1]]; bound {
			continue
		}
		// A plain rebinding (`const err = error as Error`) carries everything
		// the bound name does.
		if r := rebindRe.FindStringSubmatch(m[2]); r != nil {
			if c, ok := h.vars[r[1]]; ok {
				h.vars[m[1]] = c
				continue
			}
		}
		if c, _ := classify(m[2], h.vars, pats); c != exNone {
			h.vars[m[1]] = c
		}
	}
}

// report returns a hit when args, written to the response at at, expose the
// handler's exception: always for its detail, for its message only when its
// type is generic and messageOK allows it.
func (h *handler) report(at int, args string, pats []exposurePattern, messageOK bool) (hit, bool) {
	c, what := classify(args, h.vars, pats)
	if c == exDetail || c == exMessage && h.generic && messageOK {
		return hit{at: at, what: what}, true
	}
	return hit{}, false
}
