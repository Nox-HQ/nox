package main

import (
	"regexp"
	"strings"
)

// sinkDef maps a dangerous function call pattern to a taint rule.
type sinkDef struct {
	Pattern *regexp.Regexp
	RuleID  string
	CWE     string
}

// goSinkSelectors are selector chains that indicate dangerous sinks in Go code.
var goSinkSelectors = []struct {
	Chain  string
	RuleID string
	CWE    string
}{
	// SQL (TAINT-001)
	{"db.Exec", "TAINT-001", "CWE-89"},
	{"db.Query", "TAINT-001", "CWE-89"},
	{"db.QueryRow", "TAINT-001", "CWE-89"},
	{"tx.Exec", "TAINT-001", "CWE-89"},
	{"tx.Query", "TAINT-001", "CWE-89"},
	{"tx.QueryRow", "TAINT-001", "CWE-89"},
	// Command (TAINT-002)
	{"exec.Command", "TAINT-002", "CWE-78"},
	{"exec.CommandContext", "TAINT-002", "CWE-78"},
	{"syscall.Exec", "TAINT-002", "CWE-78"},
	// XSS (TAINT-003)
	{"template.HTML", "TAINT-003", "CWE-79"},
	{"w.Write", "TAINT-003", "CWE-79"},
	{"fmt.Fprintf", "TAINT-003", "CWE-79"},
	// File (TAINT-004)
	{"os.Open", "TAINT-004", "CWE-22"},
	{"os.ReadFile", "TAINT-004", "CWE-22"},
	{"os.WriteFile", "TAINT-004", "CWE-22"},
	{"os.Create", "TAINT-004", "CWE-22"},
}

// MatchGoSink checks if a flattened selector chain matches a Go sink.
func MatchGoSink(chain string) (ruleID, cwe string, matched bool) {
	for _, s := range goSinkSelectors {
		if strings.Contains(chain, s.Chain) {
			return s.RuleID, s.CWE, true
		}
	}
	return "", "", false
}

// pythonSinks are regex patterns for Python sinks.
var pythonSinks = []sinkDef{
	// SQL (TAINT-001)
	{regexp.MustCompile(`cursor\.execute\(`), "TAINT-001", "CWE-89"},
	{regexp.MustCompile(`db\.execute\(`), "TAINT-001", "CWE-89"},
	{regexp.MustCompile(`connection\.execute\(`), "TAINT-001", "CWE-89"},
	// Command (TAINT-002)
	{regexp.MustCompile(`os\.system\(`), "TAINT-002", "CWE-78"},
	{regexp.MustCompile(`subprocess\.call\(`), "TAINT-002", "CWE-78"},
	{regexp.MustCompile(`subprocess\.run\(`), "TAINT-002", "CWE-78"},
	{regexp.MustCompile(`subprocess\.Popen\(`), "TAINT-002", "CWE-78"},
	{regexp.MustCompile(`os\.popen\(`), "TAINT-002", "CWE-78"},
	// XSS (TAINT-003)
	{regexp.MustCompile(`Markup\(`), "TAINT-003", "CWE-79"},
	{regexp.MustCompile(`mark_safe\(`), "TAINT-003", "CWE-79"},
	{regexp.MustCompile(`render_template_string\(`), "TAINT-003", "CWE-79"},
	// File (TAINT-004)
	{regexp.MustCompile(`open\(`), "TAINT-004", "CWE-22"},
	{regexp.MustCompile(`shutil\.copy\(`), "TAINT-004", "CWE-22"},
	// Code/Deser (TAINT-005)
	{regexp.MustCompile(`pickle\.loads?\(`), "TAINT-005", "CWE-94"},
	{regexp.MustCompile(`yaml\.load\(`), "TAINT-005", "CWE-94"},
	{regexp.MustCompile(`yaml\.unsafe_load\(`), "TAINT-005", "CWE-94"},
	{regexp.MustCompile(`\beval\(`), "TAINT-005", "CWE-94"},
}

// jsSinks are regex patterns for JavaScript/TypeScript sinks.
var jsSinks = []sinkDef{
	// SQL (TAINT-001)
	{regexp.MustCompile(`db\.query\(`), "TAINT-001", "CWE-89"},
	{regexp.MustCompile(`connection\.query\(`), "TAINT-001", "CWE-89"},
	{regexp.MustCompile(`pool\.query\(`), "TAINT-001", "CWE-89"},
	{regexp.MustCompile(`knex\.raw\(`), "TAINT-001", "CWE-89"},
	// Command (TAINT-002)
	{regexp.MustCompile(`child_process\.exec\(`), "TAINT-002", "CWE-78"},
	{regexp.MustCompile(`child_process\.execSync\(`), "TAINT-002", "CWE-78"},
	{regexp.MustCompile(`child_process\.spawn\(`), "TAINT-002", "CWE-78"},
	// XSS (TAINT-003)
	{regexp.MustCompile(`\.innerHTML\s*=`), "TAINT-003", "CWE-79"},
	{regexp.MustCompile(`\.outerHTML\s*=`), "TAINT-003", "CWE-79"},
	{regexp.MustCompile(`document\.write\(`), "TAINT-003", "CWE-79"},
	// File (TAINT-004)
	{regexp.MustCompile(`fs\.readFile\(`), "TAINT-004", "CWE-22"},
	{regexp.MustCompile(`fs\.writeFile\(`), "TAINT-004", "CWE-22"},
	{regexp.MustCompile(`fs\.readFileSync\(`), "TAINT-004", "CWE-22"},
	{regexp.MustCompile(`fs\.writeFileSync\(`), "TAINT-004", "CWE-22"},
	// Code/Deser (TAINT-005)
	{regexp.MustCompile(`\beval\(`), "TAINT-005", "CWE-94"},
	{regexp.MustCompile(`\bFunction\(`), "TAINT-005", "CWE-94"},
}

// MatchTextSink checks if a line matches a sink pattern for the given language.
func MatchTextSink(line, lang string) (ruleID, cwe string, matched bool) {
	var sinks []sinkDef
	switch lang {
	case "python":
		sinks = pythonSinks
	case "javascript", "typescript":
		sinks = jsSinks
	default:
		return "", "", false
	}

	for _, s := range sinks {
		if s.Pattern.MatchString(line) {
			return s.RuleID, s.CWE, true
		}
	}
	return "", "", false
}

// goSanitizers are Go selector chains that clean tainted data.
var goSanitizers = []string{
	"html.EscapeString",
	"url.QueryEscape",
	"strconv.Atoi",
	"strconv.ParseInt",
	"template.HTMLEscapeString",
}

// pythonSanitizers are Python function patterns that clean tainted data.
var pythonSanitizers = []*regexp.Regexp{
	regexp.MustCompile(`\bescape\(`),
	regexp.MustCompile(`bleach\.clean\(`),
	regexp.MustCompile(`\bint\(`),
	regexp.MustCompile(`str\(int\(`),
}

// jsSanitizers are JS function patterns that clean tainted data.
var jsSanitizers = []*regexp.Regexp{
	regexp.MustCompile(`encodeURIComponent\(`),
	regexp.MustCompile(`\bparseInt\(`),
	regexp.MustCompile(`\bNumber\(`),
}

// IsGoSanitizer checks if a selector chain is a known Go sanitizer.
func IsGoSanitizer(chain string) bool {
	for _, s := range goSanitizers {
		if strings.Contains(chain, s) {
			return true
		}
	}
	return false
}

// IsTextSanitizer checks if a line contains a sanitizer for the given language.
func IsTextSanitizer(line, lang string) bool {
	var patterns []*regexp.Regexp
	switch lang {
	case "python":
		patterns = pythonSanitizers
	case "javascript", "typescript":
		patterns = jsSanitizers
	default:
		return false
	}

	for _, p := range patterns {
		if p.MatchString(line) {
			return true
		}
	}
	return false
}
