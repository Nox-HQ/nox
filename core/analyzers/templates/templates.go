// Package templates reports server-side template output that is written to
// the page without HTML escaping (XSS-001, CWE-79).
//
// WHY THIS EXISTS. Jinja, Django, EJS, JSF and Struts all escape what a
// template prints unless the template says not to. The taint engine reads
// code, so it never saw the place where the escaping is switched off: the
// template. On the RealVuln dev split, three in four reflected or stored XSS
// labels in Python and Node web apps sit on a template line, and nox reported
// none of them.
//
// WHY IT IS NOT A TAINT RULE. Most of those labels are stored XSS: a value read
// from the database (`{{ post.text | safe }}`) and printed raw. A database read
// is not a taint source, so a taint-gated rule could not reach them. What is
// certain is the template's own decision to switch escaping off; whether the
// value can carry markup is not. So the rule reports the decision, at low
// confidence, the way a reviewer would flag it.
//
// WHAT IT READS, per engine:
//
//   - Jinja, Django and Nunjucks (.html, .htm, .jinja, .jinja2, .j2): an output
//     `{{ expr | safe }}`, and every `{{ expr }}` inside an
//     `{% autoescape false %}` (or `off`) block. A .html file is read as one of
//     these only under a templates/ directory or when it contains `{%`, so an
//     Angular or Vue template's `{{ x | pipe }}` is not read as Jinja.
//   - EJS (.ejs): an unescaped output tag `<%- expr %>`.
//   - JSF, Facelets and Struts (.xhtml, .jsp, .jspx, .tag): a tag with
//     `escape="false"` or `escapeHtml="false"`; in JSP, an expression
//     `<%= ... %>` that prints a request parameter or header directly.
//
// WHAT IT LEAVES OUT, because the value is HTML the framework built, not data:
//
//   - EJS `<%- body %>` (a layout inserting the page it wraps) and
//     `<%- include(...) %>`, `partial`, `block`, `script`, `style`,
//     `defineContent`;
//   - Django `form|safe`, `form.<field>|safe`, `field.help_text|safe` (help text
//     the developer wrote), `csrf_token|safe`;
//   - a string literal marked safe, and output filtered through `escape`/`e`.
//
// KNOWN LIMITS: Thymeleaf `th:utext` and Vue `v-html` are not reported; most
// of their uses print markup the application built, and on the dev split
// fewer than one in ten was labelled. JSP EL (`${x}` in template text, also
// unescaped) and Twig's `|raw` are not read.
package templates

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// ruleRawOutput is the one rule this analyzer emits. XSS-* is a new
// namespace: this is not a data flow (TAINT-*) but a template's own setting.
const ruleRawOutput = "XSS-001"

// Analyzer reports unescaped template output.
type Analyzer struct{}

// NewAnalyzer constructs the template analyzer.
func NewAnalyzer() *Analyzer { return &Analyzer{} }

// Rules returns the rules this analyzer can emit, for the rule catalogue.
func (a *Analyzer) Rules() *rules.RuleSet {
	rs := rules.NewRuleSet()
	rs.Add(&rules.Rule{
		ID:          ruleRawOutput,
		Version:     "1.0",
		Description: "Template prints a value without HTML escaping",
		// Medium: if the value can carry markup it is XSS, reflected or stored,
		// in every browser that renders the page.
		Severity: findings.SeverityMedium,
		// Low: the template's decision is certain, where the value comes from
		// is not. Much raw output prints HTML the application built itself.
		Confidence: findings.ConfidenceLow,
		Tags:       []string{"xss", "templates", "owasp-a03"},
		Remediation: "This template prints the value without HTML escaping, so any markup in it runs in the reader's browser. " +
			"If the value can contain anything a user wrote -- a form field, a stored comment, a profile name, a request parameter -- remove the marker " +
			"(`| safe`, `{% autoescape false %}`, `<%-`, `escape=\"false\"`) and let the engine escape it. " +
			"If the value must render as HTML, sanitize it with an allow-list HTML sanitizer (bleach, nh3, DOMPurify, OWASP Java HTML Sanitizer) " +
			"where it is produced, and keep the raw output only for that sanitized field. " +
			"If the value is HTML the application itself built from fixed markup, record that with a nox:ignore comment.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/79.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
		},
		Metadata: map[string]string{"cwe": "CWE-79"},
	})
	return rs
}

var (
	// Jinja/Django/Nunjucks.
	jinjaOutput        = regexp.MustCompile(`\{\{-?(.*?)-?\}\}`)
	jinjaSafeFilter    = regexp.MustCompile(`\|\s*safe\b`)
	jinjaEscapeFilter  = regexp.MustCompile(`\|\s*(?:escape|e|forceescape|striptags)\b`)
	jinjaAutoescapeOff = regexp.MustCompile(`\{%-?\s*autoescape\s+(?:false|off)\s*-?%\}`)
	jinjaAutoescapeEnd = regexp.MustCompile(`\{%-?\s*endautoescape\s*-?%\}`)
	jinjaComment       = regexp.MustCompile(`(?s)\{#.*?#\}`)
	jinjaTag           = []byte("{%")
	// Framework-built HTML: a Django form or one of its fields, a field's help
	// text, the CSRF token.
	jinjaFrameworkHTML = regexp.MustCompile(`^(?:form(?:\.[A-Za-z_]\w*)?|[A-Za-z_]\w*\.help_text|csrf_token|csrf_input)$`)
	stringLiteral      = regexp.MustCompile(`^(?:"[^"]*"|'[^']*')$`)

	// EJS.
	ejsRawOutput = regexp.MustCompile(`<%-([\s\S]*?)-?%>`)
	// Layout and partial helpers whose output is another template.
	ejsFrameworkHTML = regexp.MustCompile(`^(?:body|(?:include|partial|block|script|style|defineContent)\b.*)$`)
	// A number, or a name plus or minus a number: a loop counter when the
	// template declares that name as one.
	ejsNumber      = regexp.MustCompile(`^\d+(?:\.\d+)?$`)
	ejsCounterExpr = regexp.MustCompile(`^([A-Za-z_]\w*)(?:\s*[+-]\s*\d+)?$`)

	// JSF, Facelets, Struts, JSP.
	markupNoEscape = regexp.MustCompile(`\bescape(?:Html)?\s*=\s*["']false["']`)
	jspRequestExpr = regexp.MustCompile(`<%=\s*request\s*\.\s*(?:getParameter|getHeader|getQueryString|getRequestURI)\b`)
	// The same expression as the attribute of a tag that includes, imports or
	// redirects: the value names a resource and is not printed.
	jspResourceAttr = regexp.MustCompile(`<(?:c:import|c:redirect|c:url|jsp:include|jsp:forward|jsp:param)\b[^>]*?<%=\s*request\s*\.`)
)

// ScanArtifacts reports unescaped template output across discovered templates.
func (a *Analyzer) ScanArtifacts(ctx context.Context, artifacts []discovery.Artifact) (*findings.FindingSet, error) {
	fs := findings.NewFindingSet()
	for _, art := range artifacts {
		if err := ctx.Err(); err != nil {
			return fs, err
		}
		kind := templateKind(art.Path)
		if kind == "" {
			continue
		}
		content, err := os.ReadFile(art.AbsPath)
		if err != nil {
			// An unreadable file is not a finding; discovery already surfaced it.
			continue
		}
		for _, f := range scanTemplate(kind, art.Path, content) {
			fs.Add(f)
		}
	}
	return fs, nil
}

// templateKind names the engine a path's extension belongs to, or "".
func templateKind(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".jinja", ".jinja2", ".j2":
		return "jinja"
	case ".html", ".htm":
		return "html"
	case ".ejs":
		return "ejs"
	case ".xhtml", ".jsp", ".jspx", ".tag":
		return "markup"
	}
	return ""
}

// scanTemplate returns the findings for one template.
func scanTemplate(kind, path string, content []byte) []findings.Finding {
	switch kind {
	case "html":
		// Read as Jinja/Django only where it is one: see the package comment.
		slashed := "/" + filepath.ToSlash(path)
		if !strings.Contains(slashed, "/templates/") && !strings.Contains(string(content), string(jinjaTag)) {
			return nil
		}
		return scanJinja(path, content)
	case "jinja":
		return scanJinja(path, content)
	case "ejs":
		return scanEJS(path, content)
	case "markup":
		return scanMarkup(path, content)
	}
	return nil
}

// scanJinja reports `| safe` outputs and outputs inside an autoescape-off
// block.
func scanJinja(path string, content []byte) []findings.Finding {
	// Blank comments out, keeping their newlines so line numbers hold.
	text := jinjaComment.ReplaceAllStringFunc(string(content), blankKeepingNewlines)
	var out []findings.Finding
	off := false
	for i, line := range strings.Split(text, "\n") {
		// Walk the line in order: an autoescape tag changes how the outputs
		// after it on the same line are read.
		pos := 0
		reported := false
		for pos < len(line) {
			rest := line[pos:]
			onIdx := indexOf(jinjaAutoescapeOff, rest)
			endIdx := indexOf(jinjaAutoescapeEnd, rest)
			outLoc := jinjaOutput.FindStringSubmatchIndex(rest)
			outIdx := -1
			if outLoc != nil {
				outIdx = outLoc[0]
			}
			next := minNonNeg(onIdx, endIdx, outIdx)
			if next < 0 {
				break
			}
			switch next {
			case onIdx:
				off = true
				pos += onIdx + len(jinjaAutoescapeOff.FindString(rest))
			case endIdx:
				off = false
				pos += endIdx + len(jinjaAutoescapeEnd.FindString(rest))
			default:
				expr := rest[outLoc[2]:outLoc[3]]
				if !reported && jinjaRaw(expr, off) {
					out = append(out, finding(path, i+1, "jinja",
						"Template output `{{ "+strings.TrimSpace(expr)+" }}` is printed without HTML escaping"))
					reported = true
				}
				pos += outLoc[1]
			}
		}
	}
	return out
}

// jinjaRaw reports whether a `{{ expr }}` prints without escaping: marked safe,
// or inside an autoescape-off block, and not framework-built HTML.
func jinjaRaw(expr string, autoescapeOff bool) bool {
	if jinjaEscapeFilter.MatchString(expr) {
		return false
	}
	if !autoescapeOff && !jinjaSafeFilter.MatchString(expr) {
		return false
	}
	value := strings.TrimSpace(strings.SplitN(expr, "|", 2)[0])
	if value == "" || stringLiteral.MatchString(value) || jinjaFrameworkHTML.MatchString(value) {
		return false
	}
	return true
}

// scanEJS reports `<%- expr %>` outputs that print a value.
func scanEJS(path string, content []byte) []findings.Finding {
	var out []findings.Finding
	lastLine := 0
	for _, m := range ejsRawOutput.FindAllSubmatchIndex(content, -1) {
		expr := strings.TrimSpace(string(content[m[2]:m[3]]))
		if expr == "" || ejsFrameworkHTML.MatchString(expr) || stringLiteral.MatchString(expr) ||
			ejsNumericValue(expr, content) {
			continue
		}
		line := 1 + strings.Count(string(content[:m[0]]), "\n")
		if line == lastLine {
			continue
		}
		lastLine = line
		out = append(out, finding(path, line, "ejs",
			"EJS output `<%- "+firstLine(expr)+" %>` is printed without HTML escaping"))
	}
	return out
}

// scanMarkup reports JSF/Facelets/Struts tags with escaping switched off, and
// JSP expressions that print a request value.
func scanMarkup(path string, content []byte) []findings.Finding {
	var out []findings.Finding
	for i, line := range strings.Split(string(content), "\n") {
		switch {
		case markupNoEscape.MatchString(line):
			out = append(out, finding(path, i+1, "jsf",
				"Tag output with escape=\"false\" is printed without HTML escaping"))
		case jspRequestExpr.MatchString(line) && !jspRequestOnlyNamesResource(line):
			out = append(out, finding(path, i+1, "jsp",
				"JSP expression prints a request value without HTML escaping"))
		}
	}
	return out
}

// ejsNumericValue reports whether an EJS expression can only be a number: a
// numeric literal, or a for-loop counter the template declares, plus or minus
// a number.
func ejsNumericValue(expr string, content []byte) bool {
	if ejsNumber.MatchString(expr) {
		return true
	}
	m := ejsCounterExpr.FindStringSubmatch(expr)
	if m == nil {
		return false
	}
	counter := regexp.MustCompile(`\bfor\s*\(\s*(?:var|let)?\s*` + regexp.QuoteMeta(m[1]) + `\s*=\s*\d+\s*;`)
	return counter.Match(content)
}

// jspRequestOnlyNamesResource reports whether every request expression on the
// line is the attribute of an include, import or redirect tag.
func jspRequestOnlyNamesResource(line string) bool {
	return len(jspResourceAttr.FindAllStringIndex(line, -1)) == len(jspRequestExpr.FindAllStringIndex(line, -1))
}

func finding(path string, line int, engine, msg string) findings.Finding {
	return findings.Finding{
		RuleID:     ruleRawOutput,
		Severity:   findings.SeverityMedium,
		Confidence: findings.ConfidenceLow,
		Message:    msg,
		Location:   findings.Location{FilePath: path, StartLine: line, EndLine: line},
		Metadata:   map[string]string{"cwe": "CWE-79", "template_engine": engine},
	}
}

func indexOf(re *regexp.Regexp, s string) int {
	if loc := re.FindStringIndex(s); loc != nil {
		return loc[0]
	}
	return -1
}

// minNonNeg returns the smallest non-negative argument, or -1.
func minNonNeg(xs ...int) int {
	best := -1
	for _, x := range xs {
		if x >= 0 && (best < 0 || x < best) {
			best = x
		}
	}
	return best
}

func blankKeepingNewlines(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' {
			return '\n'
		}
		return ' '
	}, s)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i]) + " ..."
	}
	return s
}
