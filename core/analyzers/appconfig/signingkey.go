package appconfig

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/nox-hq/nox/core/findings"
)

// RuleSigningKey (APPCFG-006) reports a key that signs tokens or sessions written into the source
// (CWE-321). Whoever reads the repository can forge a session or a JWT the
// application accepts. The secrets rules find a key by its entropy or a
// vendor's format; a signing key is usually neither ('keyboard cat',
// 'hardsecret', 'dev-only-change-me'), and is found here by where it is used:
//
//   - passed as the key to jwt.sign / jwt.verify / jwt.encode / jwt.decode,
//     Algorithm.HMAC*, signWith, setSigningKey;
//   - the secret of express-session, cookie-session or cookie-parser;
//   - assigned to a name that is a secret or a signing key (app.secret_key,
//     SECRET_KEY, JWT_SECRET, accessTokenSecret), including as the fallback
//     of an environment lookup (os.getenv("SECRET_KEY", "change-me"),
//     process.env.JWT_SECRET || 'secret'): the fallback is what runs wherever
//     the variable is unset.
//
// A value that reads as the NAME of a variable (JWT_SECRET, ${SECRET}) or is
// empty is not a key and is not reported.
const RuleSigningKey = "APPCFG-006"

// lit is a quoted literal; group 1 is its text.
const lit = `["'\x60]([^"'\x60\n]+)["'\x60]`

// secretName is an identifier naming a secret or a signing key. Names that
// hold something about a secret rather than the secret are excluded
// afterwards (secretName, secret_id, secretsPath).
const secretName = `[A-Za-z_]*(?:[Ss]ecret|SECRET|[Ss]igning_?[Kk]ey|SIGNING_?KEY|[Jj]wt_?[Kk]ey|JWT_?KEY|[Hh]mac_?[Kk]ey|HMAC_?KEY)[A-Za-z0-9_]*`

var (
	jsEnvFallback = `(?:process\s*\.\s*env\s*(?:\.\s*\w+|\[\s*["']\w+["']\s*\])\s*(?:\|\||\?\?)\s*)?`
	pyEnvFallback = `(?:os\s*\.\s*(?:getenv|environ\s*\.\s*get)\s*\(\s*["']\w+["']\s*,\s*)?`
)

var signingKeyRules = []rule{{
	id: RuleSigningKey, cwe: "CWE-321", severity: findings.SeverityHigh,
	message:     "Key that signs tokens or sessions is written in the source",
	description: "A literal used as a JWT, session or HMAC signing key (jwt.sign/verify, express-session secret, cookie-parser, app.secret_key, SECRET_KEY, Algorithm.HMAC256, signWith), including as the fallback of an environment lookup",
	remediation: "Read the key from a secret store or the environment at startup, and fail to start when it is missing rather than falling back to a literal; rotate the key that was committed, since every token or session signed with it can be forged.",
	tags:        []string{"secrets", "jwt", "session", "owasp-a02"},
	patterns: []pattern{
		// JavaScript / TypeScript.
		{langs: js, need: "jwt", valueOK: isKeyValue, fileOK: notSigningTest, re: regexp.MustCompile(`\bjwt\s*\.\s*(?:sign|verify)\s*\([^,()]*(?:\([^()]*\))?[^,()]*,\s*` + jsEnvFallback + lit)},
		{langs: js, need: "ecret", valueOK: isKeyValue, fileOK: notSigningTest, re: regexp.MustCompile(`\bsecret\s*:\s*` + jsEnvFallback + lit)},
		{langs: js, need: "cookieParser(", valueOK: isKeyValue, fileOK: notSigningTest, re: regexp.MustCompile(`\bcookieParser\s*\(\s*` + lit)},
		{langs: js, need: "keys", near: "ession", valueOK: isKeyValue, fileOK: notSigningTest, re: regexp.MustCompile(`\bkeys\s*:\s*\[\s*` + lit)},
		{langs: js, need: "ecret|ECRET", valueOK: isKeyValue, fileOK: notSigningTest, re: regexp.MustCompile(`(?m)(?:\b(?:const|let|var)\s+|^\s*(?:readonly\s+|private\s+|static\s+)*)` + `(` + secretName + `)\s*(?::\s*string\s*)?=\s*` + jsEnvFallback + lit), nameOK: isSecretName},
		{langs: js, need: "ecret|ECRET", valueOK: isKeyValue, fileOK: notSigningTest, re: regexp.MustCompile(`(?m)^\s*(` + secretName + `)\s*:\s*` + jsEnvFallback + lit), nameOK: isSecretName},

		// Python.
		{langs: py, need: "secret_key", valueOK: isKeyValue, fileOK: notSigningTest, re: regexp.MustCompile(`\.\s*secret_key\s*=\s*` + pyEnvFallback + lit)},
		{langs: py, need: "jwt", valueOK: isKeyValue, fileOK: notSigningTest, re: regexp.MustCompile(`\bjwt\s*\.\s*(?:encode|decode)\s*\([^,()]*(?:\([^()]*\))?[^,()]*,\s*` + pyEnvFallback + lit)},
		{langs: py, need: "ECRET", valueOK: isKeyValue, fileOK: notSigningTest, re: regexp.MustCompile(`\[\s*["']([A-Z_]*SECRET[A-Z_]*)["']\s*\]\s*=\s*` + pyEnvFallback + lit), nameOK: isSecretName},
		{langs: py, need: "ecret|ECRET", valueOK: isKeyValue, fileOK: notSigningTest, re: regexp.MustCompile(`(?m)^\s*(` + secretName + `)\s*(?::\s*str\s*)?=\s*` + pyEnvFallback + lit), nameOK: isSecretName},

		// Java / Kotlin.
		{langs: java, need: "HMAC", valueOK: isKeyValue, fileOK: notSigningTest, re: regexp.MustCompile(`\bAlgorithm\s*\.\s*HMAC(?:256|384|512)\s*\(\s*` + lit)},
		{langs: java, need: "SigningKey", valueOK: isKeyValue, fileOK: notSigningTest, re: regexp.MustCompile(`\.\s*setSigningKey\s*\(\s*` + lit)},
		{langs: java, need: "signWith", valueOK: isKeyValue, fileOK: notSigningTest, re: regexp.MustCompile(`\.\s*signWith\s*\(\s*(?:SignatureAlgorithm\s*\.\s*\w+\s*,\s*)?` + lit)},
		{langs: java, need: "ecret|ECRET", valueOK: isKeyValue, fileOK: notSigningTest, re: regexp.MustCompile(`\bString\s+(` + secretName + `)\s*=\s*` + lit), nameOK: isSecretName},
	},
}}

// isKeyValue rejects a literal that is not a key: empty, a variable's name
// (JWT_SECRET), an interpolation, or a placeholder for an absent value.
func isKeyValue(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || strings.Contains(v, "${") || strings.Contains(v, "{{") {
		return false
	}
	if envName.MatchString(v) {
		return false
	}
	switch strings.ToLower(v) {
	case "none", "null", "undefined", "<secret>", "xxx", "***", "not set", "changeme-not-set":
		return false
	}
	return strings.ContainsFunc(v, func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }) // "[....]" is a placeholder
}

// signingTestPath is test code by directory, for this rule: a signing key in
// a test is the test's own (2faSpec's TOTP secrets, an e2e JWT secret), and
// the shared source.IsTestPath deliberately does not treat a bare test/
// directory as test code.
func signingTestPath(path string) bool {
	p := "/" + strings.ReplaceAll(strings.ToLower(path), "\\", "/")
	for _, d := range []string{"/test/", "/tests/", "/e2e/", "/spec/"} {
		if strings.Contains(p, d) {
			return true
		}
	}
	base := p[strings.LastIndexByte(p, '/')+1:]
	return strings.Contains(base, "-spec.") || strings.Contains(base, "_spec.")
}

var envName = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`)

// isSecretName rejects an identifier that holds something ABOUT a secret.
func isSecretName(name string) bool {
	n := strings.ToLower(name)
	for _, w := range []string{"name", "id", "path", "file", "header", "param", "type", "env", "label", "url", "prefix", "len", "field", "arn", "ref", "manager", "client_secret", "clientsecret", "store", "version", "rotation", "expir", "ttl", "algorithm", "alg", "preview", "hint", "tag", "show", "encrypted", "expected", "mask"} {
		if strings.Contains(n, w) {
			return false
		}
	}
	return true
}

func notSigningTest(path string) bool { return !signingTestPath(path) && !exampleFile(path) }

// exampleFile is a file named as documentation of a configuration
// (settings.example.py, config_sample.js, env_template.ts,
// clean_env_example.py): its keys are a template for the reader to replace,
// not the ones the application runs with. A placeholder in a module that
// runs, such as a pydantic default "change-me-in-production", is reported:
// it is the key wherever the variable is unset.
func exampleFile(path string) bool {
	p := strings.ReplaceAll(strings.ToLower(path), "\\", "/")
	base := p[strings.LastIndexByte(p, '/')+1:]
	for _, w := range []string{"example", "sample", "template"} {
		if strings.Contains(base, w) {
			return true
		}
	}
	return false
}
