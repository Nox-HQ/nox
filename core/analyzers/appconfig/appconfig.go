// Package appconfig reports application security settings written into the
// source: a web framework's debug mode switched on, cross-origin access opened
// to every origin, a JSON Web Token read without its signature checked.
//
// Each is a decision the developer wrote down as a literal -- `debug=True`,
// `"*"`, `verify=False`, a decode call that by its definition does not verify
// -- so each is reported where it is written, with high confidence that the
// setting is what the line says. Whether it reaches production is decided by
// deployment, which a file does not show; settings files named for local or
// development use and test paths are therefore skipped.
package appconfig

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/rules"
	"github.com/nox-hq/nox/core/source"
)

// Rule IDs.
const (
	RuleDebugMode  = "APPCFG-001"
	RuleCORSAny    = "APPCFG-002"
	RuleJWTNoVerif = "APPCFG-003"
)

// pattern is one way of writing a setting, in the languages whose files it
// is matched against.
type pattern struct {
	langs []lexctx.Lang
	// need is a literal every match contains. A file without it is not
	// matched against re at all: most files hold none of these settings, and
	// a regex that cannot start from a literal scans the whole file.
	need string
	re   *regexp.Regexp
	// fileOK, when set, restricts the pattern to files it accepts (Django's
	// DEBUG = True means something only in a settings module).
	fileOK func(path string) bool
}

type rule struct {
	id, cwe, message, description, remediation string
	severity                                   findings.Severity
	tags                                       []string
	patterns                                   []pattern
}

var (
	py   = []lexctx.Lang{lexctx.LangPython}
	js   = []lexctx.Lang{lexctx.LangJavaScript}
	java = []lexctx.Lang{lexctx.LangJava, lexctx.LangKotlin}
	goL  = []lexctx.Lang{lexctx.LangGo}
)

var builtin = []rule{
	{
		id: RuleDebugMode, cwe: "CWE-215", severity: findings.SeverityMedium,
		message:     "Web framework debug mode is enabled in source",
		description: "Web framework debug mode enabled in source (Flask app.run(debug=True), app.debug = True, DEBUG config, Django settings DEBUG = True, FastAPI(debug=True))",
		remediation: "Debug mode serves stack traces, local variables and, in Flask/Werkzeug, an interactive debugger that runs code. Read it from the environment and default to off: `debug=os.environ.get(\"FLASK_DEBUG\") == \"1\"`, Django `DEBUG = env.bool(\"DEBUG\", False)`.",
		tags:        []string{"debug", "configuration", "owasp-a05"},
		patterns: []pattern{
			{langs: py, need: "debug", re: regexp.MustCompile(`\b[A-Za-z_]\w*\.run\s*\([^)\n]*\bdebug\s*=\s*True\b`)},
			{langs: py, need: ".debug", re: regexp.MustCompile(`(?m)^\s*[A-Za-z_]\w*\.debug\s*=\s*True\b`)},
			{langs: py, need: "DEBUG", re: regexp.MustCompile(`\.config\s*\[\s*['"]DEBUG['"]\s*\]\s*=\s*True\b`)},
			{langs: py, need: "DEBUG", re: regexp.MustCompile(`\.config\.update\s*\([^)\n]*\bDEBUG\s*=\s*True\b`)},
			{langs: py, need: "FastAPI", re: regexp.MustCompile(`\bFastAPI\s*\([^)\n]*\bdebug\s*=\s*True\b`)},
			{langs: py, need: "DEBUG", re: regexp.MustCompile(`(?m)^DEBUG\s*=\s*True\b`), fileOK: isDjangoSettings},
		},
	},
	{
		id: RuleCORSAny, cwe: "CWE-942", severity: findings.SeverityMedium,
		message:     "Cross-origin access is allowed from any origin",
		description: "CORS policy allows every origin (\"*\", an argument-less cors()/CORS(app), allow-all settings)",
		remediation: "List the origins that may call the API. With credentials, a wildcard or a reflected origin lets any site read authenticated responses. Spring: allowedOrigins(\"https://app.example.com\"); Express: cors({ origin: [\"https://app.example.com\"] }); Flask-CORS: CORS(app, origins=[...]); FastAPI: allow_origins=[...].",
		tags:        []string{"cors", "configuration", "owasp-a05"},
		patterns: []pattern{
			{langs: java, need: "llowedOrigin", re: regexp.MustCompile(`\.\s*(?:addAllowedOrigin|addAllowedOriginPattern|allowedOrigins|allowedOriginPatterns|setAllowedOrigins|setAllowedOriginPatterns)\s*\(\s*(?:(?:List|Arrays)\s*\.\s*(?:of|asList)\s*\(\s*)?"\*"`)},
			{langs: java, need: "@CrossOrigin", re: regexp.MustCompile(`@CrossOrigin\s*(?:\(\s*\)|\(\s*(?:origins\s*=\s*|value\s*=\s*)?\{?\s*"\*"|$|\n)`)},
			{langs: append(append([]lexctx.Lang{}, java...), js...), need: "ccess-", re: regexp.MustCompile(`(?i)\b(?:setHeader|addHeader|header|set)\s*\(\s*["']Access-Control-Allow-Origin["']\s*,\s*["']\*["']`)},
			{langs: js, need: "cors", re: regexp.MustCompile(`\bcors\s*\(\s*\)`)},
			{langs: js, need: "cors", re: regexp.MustCompile(`\bcors\s*\(\s*\{[^}]*\borigin\s*:\s*(?:["']\*["']|true\b)`)},
			{langs: py, need: "CORS", re: regexp.MustCompile(`\bCORS\s*\(\s*[A-Za-z_]\w*\s*\)`)},
			{langs: py, need: "CORS", re: regexp.MustCompile(`\bCORS\s*\([^)\n]*\borigins['"]?\s*[:=]\s*["']\*["']`)},
			{langs: py, need: "allow_origins", re: regexp.MustCompile(`\ballow_origins\s*=\s*\[\s*["']\*["']\s*\]`)},
			{langs: py, need: "CORS_", re: regexp.MustCompile(`(?m)^\s*CORS_(?:ORIGIN_ALLOW_ALL|ALLOW_ALL_ORIGINS)\s*=\s*True\b`)},
			{langs: py, need: "Access-Control-Allow-Origin", re: regexp.MustCompile(`\[\s*["']Access-Control-Allow-Origin["']\s*\]\s*=\s*["']\*["']`)},
			{langs: py, need: "Access-Control-Allow-Origin", re: regexp.MustCompile(`\.(?:set|add|send_header)\s*\(\s*["']Access-Control-Allow-Origin["']\s*,\s*["']\*["']`)},
		},
	},
	{
		id: RuleJWTNoVerif, cwe: "CWE-347", severity: findings.SeverityHigh,
		message:     "JSON Web Token is read without verifying its signature",
		description: "JWT decoded without signature verification (jwt.decode with verification off, auth0 JWT.decode, jjwt parse(), jsonwebtoken decode(), golang-jwt ParseUnverified, the none algorithm)",
		remediation: "Verify the token before trusting any claim in it: PyJWT jwt.decode(token, key, algorithms=[\"RS256\"]); auth0 JWT.require(algorithm).build().verify(token); jjwt parseSignedClaims / parseClaimsJws; jsonwebtoken jwt.verify; golang-jwt jwt.Parse with a key function. Never accept the none algorithm.",
		tags:        []string{"jwt", "authentication", "owasp-a02"},
		patterns: []pattern{
			{langs: py, need: "verify", re: regexp.MustCompile(`\bjwt\.decode\s*\([^)\n]*\bverify\s*=\s*False\b`)},
			{langs: py, need: "verify_signature", re: regexp.MustCompile(`["']verify_signature["']\s*:\s*False\b`)},
			{langs: append(append([]lexctx.Lang{}, py...), js...), need: "none", re: regexp.MustCompile(`\balgorithms\s*[=:]\s*\[\s*["']none["']`)},
			{langs: java, need: "JWT", re: regexp.MustCompile(`\bJWT\s*\.\s*decode\s*\(`)},
			{langs: java, need: "Jwts", re: regexp.MustCompile(`\bJwts\s*\.\s*parser(?:Builder)?\s*\(\s*\)[^;]*?\.\s*parse\s*\(`)},
			{langs: js, need: "decode", re: regexp.MustCompile(`\b(?:jwt|jsonwebtoken)\s*\.\s*decode\s*\(`)},
			{langs: goL, need: "ParseUnverified", re: regexp.MustCompile(`\.\s*ParseUnverified\s*\(`)},
		},
	},
}

// isDjangoSettings accepts a Django settings module other than one named for
// local or development use.
func isDjangoSettings(path string) bool {
	p := strings.ToLower(filepath.ToSlash(path))
	base := filepath.Base(p)
	inSettings := base == "settings.py" || strings.Contains(p, "/settings/") || strings.HasPrefix(base, "settings_")
	if !inSettings {
		return false
	}
	for _, dev := range []string{"local", "dev", "development", "test", "ci"} {
		if strings.TrimSuffix(base, ".py") == dev || strings.Contains(base, "_"+dev) || strings.Contains(base, dev+"_") {
			return false
		}
	}
	return true
}

// Analyzer reports the settings in builtin.
type Analyzer struct{}

// NewAnalyzer returns the analyzer.
func NewAnalyzer() *Analyzer { return &Analyzer{} }

// Rules returns the analyzer's rules for the catalog.
func (a *Analyzer) Rules() *rules.RuleSet {
	rs := rules.NewRuleSet()
	for _, r := range builtin {
		rs.Add(&rules.Rule{
			ID:          r.id,
			Version:     "1.0",
			Description: r.description,
			Severity:    r.severity,
			// High: the setting is written as a literal on the line reported.
			Confidence:  findings.ConfidenceHigh,
			Tags:        r.tags,
			Remediation: r.remediation,
			References:  []string{"https://cwe.mitre.org/data/definitions/" + strings.TrimPrefix(r.cwe, "CWE-") + ".html"},
			Metadata:    map[string]string{"cwe": r.cwe},
		})
	}
	return rs
}

// langByExt is the language each scanned extension is read as.
var langByExt = map[string]lexctx.Lang{
	".py": lexctx.LangPython, ".java": lexctx.LangJava, ".kt": lexctx.LangKotlin, ".go": lexctx.LangGo,
	".js": lexctx.LangJavaScript, ".jsx": lexctx.LangJavaScript, ".mjs": lexctx.LangJavaScript, ".cjs": lexctx.LangJavaScript,
	".ts": lexctx.LangJavaScript, ".tsx": lexctx.LangJavaScript, ".mts": lexctx.LangJavaScript, ".cts": lexctx.LangJavaScript,
}

// triggers is a cheap prefilter: a file that names none of these cannot match.
var triggers = [][]byte{[]byte("debug"), []byte("DEBUG"), []byte("rigin"), []byte("CORS"), []byte("cors"), []byte("decode"), []byte("parse"), []byte("Unverified"), []byte("none")}

// ScanArtifacts reports the settings across the discovered source files.
func (a *Analyzer) ScanArtifacts(ctx context.Context, artifacts []discovery.Artifact) (*findings.FindingSet, error) {
	fs := findings.NewFindingSet()
	for _, art := range artifacts {
		if err := ctx.Err(); err != nil {
			return fs, err
		}
		lang, ok := langByExt[strings.ToLower(filepath.Ext(art.Path))]
		if !ok || source.IsTestPath(art.Path) {
			continue
		}
		content, err := os.ReadFile(art.AbsPath)
		if err != nil {
			continue
		}
		for _, f := range ScanFile(art.Path, lang, content) {
			fs.Add(f)
		}
	}
	return fs, nil
}

// ScanFile returns the findings in one file. A match counts only when it
// starts in code: the raw text is matched so literals such as "*" are visible,
// and a match whose first byte is inside a comment or string is dropped.
func ScanFile(path string, lang lexctx.Lang, content []byte) []findings.Finding {
	if !hasTrigger(content) {
		return nil
	}
	var masked []byte
	var out []findings.Finding
	seen := map[string]bool{}
	for _, r := range builtin {
		for _, p := range r.patterns {
			if !slices.Contains(p.langs, lang) || (p.fileOK != nil && !p.fileOK(path)) || !bytes.Contains(content, []byte(p.need)) {
				continue
			}
			for _, loc := range p.re.FindAllIndex(content, -1) {
				start := firstNonSpace(content, loc[0], loc[1])
				if masked == nil {
					masked = lexctx.MaskNonCode(lang, content)
				}
				if start < 0 || masked[start] != content[start] {
					continue // in a comment or a string
				}
				line := lexctx.LineForOffset(content, start)
				key := r.id + ":" + strconv.Itoa(line)
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, findings.Finding{
					RuleID:     r.id,
					Severity:   r.severity,
					Confidence: findings.ConfidenceHigh,
					Message:    r.message,
					Location:   findings.Location{FilePath: path, StartLine: line, EndLine: line},
					Metadata:   map[string]string{"cwe": r.cwe, "language": lang.String()},
				})
			}
		}
	}
	return out
}

func hasTrigger(content []byte) bool {
	for _, t := range triggers {
		if bytes.Contains(content, t) {
			return true
		}
	}
	return false
}

// firstNonSpace is the offset of the first non-whitespace byte in [from, to),
// or -1. A pattern anchored at a line start begins with indentation, which is
// code in the mask either way; the decision is made on what follows it.
func firstNonSpace(b []byte, from, to int) int {
	for i := from; i < to; i++ {
		switch b[i] {
		case ' ', '\t', '\n', '\r':
			continue
		}
		return i
	}
	return -1
}
