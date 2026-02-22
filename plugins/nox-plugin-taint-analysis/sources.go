package main

import (
	"regexp"
	"strings"
)

// sourcePattern describes how to recognize an untrusted input source.
type sourcePattern struct {
	Pattern *regexp.Regexp
	Kind    string // taint kind for TaintSource.Kind
}

// goSourceSelectors are selector chains that indicate taint in Go code.
// Matched against the flattened selector chain from AST analysis.
var goSourceSelectors = []struct {
	Chain string
	Kind  string
}{
	{"r.URL.Query", "http_query"},
	{"r.FormValue", "http_body"},
	{"r.PostFormValue", "http_body"},
	{"r.Header.Get", "http_header"},
	{"r.PathValue", "http_query"},
	{"r.Body", "http_body"},
	{"io.ReadAll", "http_body"},
	{"os.Args", "cli_arg"},
	{"os.Getenv", "env_var"},
	{"flag.Arg", "cli_arg"},
	{"bufio.NewScanner", "stdin"},
	{"fmt.Scan", "stdin"},
	{"fmt.Scanln", "stdin"},
	{"fmt.Scanf", "stdin"},
}

// MatchGoSource checks if a flattened selector chain matches a Go taint source.
func MatchGoSource(chain string) (string, bool) {
	for _, s := range goSourceSelectors {
		if strings.Contains(chain, s.Chain) {
			return s.Kind, true
		}
	}
	return "", false
}

// pythonSourcePatterns are regex patterns for Python taint sources.
var pythonSourcePatterns = []sourcePattern{
	{regexp.MustCompile(`request\.args`), "http_query"},
	{regexp.MustCompile(`request\.form`), "http_body"},
	{regexp.MustCompile(`request\.data`), "http_body"},
	{regexp.MustCompile(`request\.get_json`), "http_body"},
	{regexp.MustCompile(`request\.headers`), "http_header"},
	{regexp.MustCompile(`request\.GET`), "http_query"},
	{regexp.MustCompile(`request\.POST`), "http_body"},
	{regexp.MustCompile(`sys\.argv`), "cli_arg"},
	{regexp.MustCompile(`os\.environ`), "env_var"},
	{regexp.MustCompile(`os\.getenv\(`), "env_var"},
	{regexp.MustCompile(`input\(`), "stdin"},
}

// jsSourcePatterns are regex patterns for JavaScript/TypeScript taint sources.
var jsSourcePatterns = []sourcePattern{
	{regexp.MustCompile(`req\.query`), "http_query"},
	{regexp.MustCompile(`req\.body`), "http_body"},
	{regexp.MustCompile(`req\.params`), "http_query"},
	{regexp.MustCompile(`req\.headers`), "http_header"},
	{regexp.MustCompile(`req\.get\(`), "http_header"},
	{regexp.MustCompile(`process\.argv`), "cli_arg"},
	{regexp.MustCompile(`process\.env`), "env_var"},
	{regexp.MustCompile(`document\.location`), "http_query"},
	{regexp.MustCompile(`window\.location`), "http_query"},
}

// MatchTextSource checks if a line matches a source pattern for the given language.
func MatchTextSource(line, lang string) (string, bool) {
	var patterns []sourcePattern
	switch lang {
	case "python":
		patterns = pythonSourcePatterns
	case "javascript", "typescript":
		patterns = jsSourcePatterns
	default:
		return "", false
	}

	for _, p := range patterns {
		if p.Pattern.MatchString(line) {
			return p.Kind, true
		}
	}
	return "", false
}
