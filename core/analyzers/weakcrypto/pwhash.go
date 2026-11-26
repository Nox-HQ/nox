// Password hashed with too little work — CRYPTO-003.
//
// CRYPTO-001 reports MD5 and SHA-1 at low confidence because it cannot see
// what the digest is for. This rule is the case where the code says: the value
// digested is a password (by its name, or the name of what the digest is
// stored as), or the function is a password KDF run with a work factor far
// below its floor. A fast digest of a password — MD5, SHA-1 and SHA-2 alike,
// salted or not — is recovered by an offline guessing attack once the hashes
// leak; CWE-916, use of password hash with insufficient computational effort.
//
// What it reads, per statement:
//
//   - a fast digest call (hashlib.md5/sha*, node createHash('sha256'),
//     CryptoJS.SHA256, Spring/Commons DigestUtils, MessageDigest, Guava
//     Hashing, a bare md5()/sha256() helper), or update/digest on a variable
//     assigned one, where a password-named identifier appears in the
//     statement: the argument, or the target the digest is stored in
//     (passwordHash = …, setPinHash(…));
//   - PBKDF2 (Java PBEKeySpec, Python pbkdf2_hmac, node pbkdf2/pbkdf2Sync)
//     with fewer than 10,000 iterations, and bcrypt with a cost below 10 —
//     both are password KDFs, so no name is needed. The count is read from a
//     literal, a `x || N` / `x ?? N` fallback, or a constant assigned a
//     literal in the same file; anything else is not reported.
//
// Not reported: a digest of a token, nonce or reset token (a random value
// needs no work factor), names about a password rather than its value
// (passwordLength, passwordPolicy), a file that queries the Pwned Passwords
// range API (which is defined over SHA-1), comments, and test files.
package weakcrypto

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/rules"
)

const pwHashRuleID = "CRYPTO-003"

// Work-factor floors below which a password KDF is reported. They are far
// under current guidance (OWASP: PBKDF2-HMAC-SHA256 600,000 iterations, bcrypt
// cost 10 or more), so a report is unambiguous rather than a judgement call.
const (
	minPBKDF2Iterations = 10000
	minBcryptCost       = 10
)

type pwFamily int

const (
	famPy pwFamily = iota
	famJS
	famJVM
)

var pwFamilyByExt = map[string]pwFamily{
	".py": famPy,
	".js": famJS, ".jsx": famJS, ".mjs": famJS, ".cjs": famJS,
	".ts": famJS, ".tsx": famJS, ".mts": famJS, ".cts": famJS,
	".java": famJVM, ".kt": famJVM, ".kts": famJVM,
}

var pwLexLang = map[pwFamily]lexctx.Lang{famPy: lexctx.LangPython, famJS: lexctx.LangJavaScript, famJVM: lexctx.LangJava}

// fastDigest matches the call that starts a fast digest, per family.
var fastDigest = map[pwFamily][]*regexp.Regexp{
	famPy: {
		regexp.MustCompile(`\bhashlib\s*\.\s*(?:md5|sha1|sha224|sha256|sha384|sha512|sha3_224|sha3_256|sha3_384|sha3_512|blake2b|blake2s|new)\s*\(`),
		regexp.MustCompile(`(?:^|[^.\w])(?:md5|sha1|sha224|sha256|sha384|sha512)\s*\(`),
	},
	famJS: {
		regexp.MustCompile("\\bcreateHash\\s*\\(\\s*['\"`](?i:md5|md4|sha-?1|sha-?224|sha-?256|sha-?384|sha-?512|sha3-\\d+)['\"`]\\s*\\)"),
		regexp.MustCompile(`\bCryptoJS\s*\.\s*(?:MD5|SHA1|SHA224|SHA256|SHA384|SHA512|SHA3)\s*\(`),
		regexp.MustCompile(`(?:^|[^.\w$])(?i:(?:hash_?)?(?:md5|sha1|sha256|sha512))\s*\(`),
	},
	famJVM: {
		regexp.MustCompile(`\bDigestUtils\s*\.\s*(?:md2|md5|sha1|sha|sha256|sha384|sha512)(?:Hex|DigestAsHex|Digest)?\s*\(`),
		regexp.MustCompile(`\bMessageDigest\s*\.\s*getInstance\s*\(\s*"(?i:MD2|MD5|SHA-?1|SHA|SHA-?224|SHA-?256|SHA-?384|SHA-?512)"\s*\)\s*\.\s*digest\s*\(`),
		regexp.MustCompile(`\bHashing\s*\.\s*(?:md5|sha1|sha256|sha384|sha512)\s*\(\s*\)`),
	},
}

// digestCtor matches a variable assigned a fast digest object, so that a
// later name.update(…) / name.digest(…) is read as the digest call.
var digestCtor = map[pwFamily]*regexp.Regexp{
	famPy:  regexp.MustCompile(`\b([A-Za-z_]\w*)\s*=\s*hashlib\s*\.\s*(?:md5|sha1|sha224|sha256|sha384|sha512|new)\s*\(`),
	famJS:  regexp.MustCompile("\\b([A-Za-z_$][\\w$]*)\\s*=\\s*(?:\\w+\\s*\\.\\s*)?createHash\\s*\\(\\s*['\"`](?i:md5|md4|sha-?1|sha-?224|sha-?256|sha-?384|sha-?512)['\"`]\\s*\\)\\s*[;\\n]"),
	famJVM: regexp.MustCompile(`\b([A-Za-z_]\w*)\s*=\s*(?:java\.security\.)?MessageDigest\s*\.\s*getInstance\s*\(\s*"(?i:MD2|MD5|SHA-?1|SHA|SHA-?224|SHA-?256|SHA-?384|SHA-?512)"`),
}

// kdfCall is a password KDF call and the argument that holds its work factor.
type kdfCall struct {
	re      *regexp.Regexp
	arg     int    // positional index of the work factor
	keyword string // keyword form of the work factor, Python
	floor   int
	what    string
}

var kdfCalls = map[pwFamily][]kdfCall{
	famPy: {
		{re: regexp.MustCompile(`\bpbkdf2_hmac\s*\(`), arg: 3, keyword: "iterations", floor: minPBKDF2Iterations, what: "PBKDF2 with %d iterations"},
		{re: regexp.MustCompile(`\bbcrypt\s*\.\s*gensalt\s*\(`), arg: 0, keyword: "rounds", floor: minBcryptCost, what: "bcrypt with cost %d"},
	},
	famJS: {
		{re: regexp.MustCompile(`\bpbkdf2(?:Sync)?\s*\(`), arg: 2, floor: minPBKDF2Iterations, what: "PBKDF2 with %d iterations"},
		{re: regexp.MustCompile(`\bbcrypt\w*\s*\.\s*(?:hash|hashSync)\s*\(`), arg: 1, floor: minBcryptCost, what: "bcrypt with cost %d"},
		{re: regexp.MustCompile(`\bbcrypt\w*\s*\.\s*(?:genSalt|genSaltSync)\s*\(`), arg: 0, floor: minBcryptCost, what: "bcrypt with cost %d"},
	},
	famJVM: {
		{re: regexp.MustCompile(`\bnew\s+(?:[\w.]+\.)?PBEKeySpec\s*\(`), arg: 2, floor: minPBKDF2Iterations, what: "PBKDF2 with %d iterations"},
	},
}

// passwordWords name a password's value; a digest of one needs a work factor.
var passwordWords = map[string]bool{
	"password": true, "passwd": true, "pwd": true, "pw": true, "passphrase": true,
	"phrase": true, "passcode": true, "pin": true, "pincode": true,
	"credential": true, "credentials": true,
}

// notPasswordValue: an identifier with one of these words names something
// about a password, or a random value that needs no work factor.
var notPasswordValue = map[string]bool{
	"token": true, "tokens": true, "nonce": true, "length": true, "len": true,
	"policy": true, "field": true, "label": true, "regex": true, "pattern": true,
	"strength": true, "hint": true, "prompt": true, "url": true, "path": true,
	"file": true, "rule": true, "rules": true, "min": true, "max": true,
}

var identRe = regexp.MustCompile(`[A-Za-z_$][\w$]*`)

// pwnedRe: the Pwned Passwords range API is defined over SHA-1 of the
// password, so a SHA-1 of a password there is the protocol, not storage.
var pwnedRe = regexp.MustCompile(`(?i)pwned|\bhibp\b`)

// definitionBefore: the match is the name of a function being defined, not a call.
var definitionBefore = regexp.MustCompile(`(?:\bfunction|\bdef|\bfun)\s*$`)

func pwHashRule() *rules.Rule {
	return &rules.Rule{
		ID:          pwHashRuleID,
		Version:     "1.0",
		Description: "Password hashed with a fast digest (MD5, SHA-1, SHA-2) or a KDF below its work-factor floor (PBKDF2 under 10,000 iterations, bcrypt cost under 10)",
		Severity:    findings.SeverityHigh,
		// Medium: that the value is a password is read from names.
		Confidence: findings.ConfidenceMedium,
		Tags:       []string{"crypto", "password-storage", "owasp-a02"},
		Remediation: "A fast digest of a password, salted or not, is reversed by offline guessing at billions of candidates a second once the stored hashes leak. " +
			"Hash passwords with a password KDF: Argon2id (m=19 MiB, t=2, p=1 or more), scrypt, bcrypt with cost 10 or more, or PBKDF2-HMAC-SHA256 with at least 600,000 iterations; " +
			"Spring Security's DelegatingPasswordEncoder / BCryptPasswordEncoder, Django's default hashers, passlib, argon2-cffi, or the bcrypt / argon2 npm packages. " +
			"Re-hash legacy digests on the user's next successful login. If the value digested here is not a password, suppress this with a nox:ignore comment saying what it is.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/916.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
		},
		Metadata: map[string]string{"cwe": "CWE-916"},
	}
}

// scanPasswordHash reports CRYPTO-003 in one file.
func scanPasswordHash(path string, content []byte) []findings.Finding {
	fam, ok := pwFamilyByExt[strings.ToLower(filepath.Ext(path))]
	if !ok {
		return nil
	}
	code := blankComments(pwLexLang[fam], content)
	masked := lexctx.MaskNonCode(pwLexLang[fam], content)
	inCode := func(at int) bool { return at < len(masked) && masked[at] == content[at] }
	pwned := pwnedRe.Match(content)
	var out []findings.Finding
	seen := map[int]bool{}
	add := func(at int, msg string) {
		line := lexctx.LineForOffset(content, at)
		if seen[line] {
			return
		}
		seen[line] = true
		out = append(out, findings.Finding{
			RuleID:     pwHashRuleID,
			Severity:   findings.SeverityHigh,
			Confidence: findings.ConfidenceMedium,
			Message:    msg,
			Location:   findings.Location{FilePath: path, StartLine: line, EndLine: line},
			Metadata:   map[string]string{"cwe": "CWE-916", "language": pwLexLang[fam].String()},
		})
	}

	if !pwned {
		starts := digestStarts(fam, code)
		for _, at := range starts {
			if inCode(at) && statementNamesPassword(code, at) {
				add(at, "A password is hashed with a fast digest; use a password KDF (Argon2id, scrypt, bcrypt, PBKDF2 with a high iteration count)")
			}
		}
	}
	for _, k := range kdfCalls[fam] {
		for _, loc := range k.re.FindAllStringIndex(code, -1) {
			if !inCode(loc[0]) {
				continue
			}
			args, ok := callArgs(code, loc[1]-1)
			if !ok {
				continue
			}
			n, ok := workFactor(code, args, k)
			if ok && n < k.floor {
				add(loc[0], "Password key derivation with too little work: "+strings.Replace(k.what, "%d", strconv.Itoa(n), 1))
			}
		}
	}
	return out
}

// digestStarts returns the offsets of every fast digest call in code.
func digestStarts(fam pwFamily, code string) []int {
	var starts []int
	for _, re := range fastDigest[fam] {
		for _, loc := range re.FindAllStringIndex(code, -1) {
			at := loc[0]
			for at < loc[1] && !isIdentByte(code[at]) {
				at++ // the leading non-identifier byte of a bare-call match
			}
			lineStart := strings.LastIndexByte(code[:at], '\n') + 1
			if definitionBefore.MatchString(code[lineStart:at]) {
				continue
			}
			starts = append(starts, at)
		}
	}
	if ctor := digestCtor[fam]; ctor != nil {
		for _, m := range ctor.FindAllStringSubmatch(code, -1) {
			use := regexp.MustCompile(`\b` + regexp.QuoteMeta(m[1]) + `\s*\.\s*(?:update|digest)\s*\(`)
			for _, loc := range use.FindAllStringIndex(code, -1) {
				starts = append(starts, loc[0])
			}
		}
	}
	return starts
}

func isIdentByte(b byte) bool {
	return b == '_' || b == '$' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

// statementNamesPassword reports whether the statement holding the call at
// `at` names a password's value: an identifier from the call on (what is
// digested), or one before it on the line that says it holds the password's
// digest (passwordHash = …, setPinHash(…)). A name before the call without a
// digest word names the result, not the input: expectedPin = sha256(id).
// A statement of a challenge-response or digest-auth protocol is not storage.
func statementNamesPassword(code string, at int) bool {
	start := strings.LastIndexByte(code[:at], '\n') + 1
	end := statementEnd(code, at)
	stmt := code[start:end]
	if strings.Contains(stmt, ":mongo:") {
		return false
	}
	ids := identRe.FindAllString(stmt, -1)
	for _, id := range ids {
		for _, w := range splitWords(id) {
			if protocolWords[w] {
				return false
			}
		}
	}
	for _, id := range identRe.FindAllString(code[start:at], -1) {
		if isPasswordName(id) && hasDigestWord(id) {
			return true
		}
	}
	for _, id := range identRe.FindAllString(code[at:end], -1) {
		if isPasswordName(id) {
			return true
		}
	}
	return false
}

// protocolWords mark a digest defined by an authentication protocol (HTTP
// Digest HA1 over the realm, a server nonce or challenge), not password storage.
var protocolWords = map[string]bool{"realm": true, "nonce": true, "challenge": true, "cnonce": true}

// digestWords say a name holds a digest.
var digestWords = map[string]bool{"hash": true, "hashed": true, "hashes": true, "digest": true, "verifier": true}

func hasDigestWord(id string) bool {
	for _, w := range splitWords(id) {
		if digestWords[w] {
			return true
		}
	}
	return false
}

// statementEnd is the offset of the first ';' or newline at bracket depth 0
// after at, at most 600 bytes on.
func statementEnd(code string, at int) int {
	limit := min(len(code), at+600)
	depth := 0
	for i := at; i < limit; i++ {
		switch code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth < 0 {
				return i
			}
		case ';':
			if depth == 0 {
				return i
			}
		case '\n':
			if depth == 0 {
				return i
			}
		}
	}
	return limit
}

func isPasswordName(id string) bool {
	if id == "pass" {
		return true
	}
	ws := splitWords(id)
	found := false
	for _, w := range ws {
		if notPasswordValue[w] {
			return false
		}
		if passwordWords[w] {
			found = true
		}
	}
	return found
}

// splitWords splits camelCase, PascalCase and snake_case into lower-case words.
func splitWords(name string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	rs := []rune(name)
	for i, r := range rs {
		switch {
		case r == '_' || r == '$':
			flush()
		case r >= 'A' && r <= 'Z':
			if i > 0 && (rs[i-1] >= 'a' && rs[i-1] <= 'z' || i+1 < len(rs) && rs[i+1] >= 'a' && rs[i+1] <= 'z' && rs[i-1] >= 'A' && rs[i-1] <= 'Z') {
				flush()
			}
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return out
}

// callArgs splits the top-level arguments of the call whose '(' is at open.
func callArgs(code string, open int) ([]string, bool) {
	depth := 0
	var args []string
	last := open + 1
	limit := min(len(code), open+800)
	for i := open; i < limit; i++ {
		switch code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				args = append(args, strings.TrimSpace(code[last:i]))
				return args, true
			}
		case ',':
			if depth == 1 {
				args = append(args, strings.TrimSpace(code[last:i]))
				last = i + 1
			}
		}
	}
	return nil, false
}

var (
	intLitRe    = regexp.MustCompile(`^\d[0-9_]*$`)
	fallbackRe  = regexp.MustCompile(`(?:\|\||\?\?|\bor)\s*(\d[0-9_]*)\s*$`)
	identOnlyRe = regexp.MustCompile(`^(?:[A-Za-z_]\w*\.)?([A-Za-z_]\w*)$`)
)

// workFactor reads the KDF's work factor: a literal, a fallback literal, or a
// constant assigned a literal in the same file.
func workFactor(code string, args []string, k kdfCall) (int, bool) {
	expr := ""
	if k.keyword != "" {
		for _, a := range args {
			if name, val, ok := strings.Cut(a, "="); ok && strings.TrimSpace(name) == k.keyword {
				expr = strings.TrimSpace(val)
			}
		}
	}
	if expr == "" && k.arg < len(args) && !strings.Contains(args[k.arg], "=") {
		expr = args[k.arg]
	}
	if expr == "" {
		return 0, false
	}
	return intValue(code, expr)
}

func intValue(code, expr string) (int, bool) {
	if intLitRe.MatchString(expr) {
		n, err := strconv.Atoi(strings.ReplaceAll(expr, "_", ""))
		return n, err == nil
	}
	if m := fallbackRe.FindStringSubmatch(expr); m != nil {
		return intValue(code, m[1])
	}
	if m := identOnlyRe.FindStringSubmatch(expr); m != nil {
		def := regexp.MustCompile(`\b` + regexp.QuoteMeta(m[1]) + `\s*(?::\s*\w+\s*)?=\s*([0-9][0-9_]*)\s*[;\n]`)
		if d := def.FindStringSubmatch(code); d != nil {
			return intValue(code, d[1])
		}
	}
	return 0, false
}

// blankComments returns content with comment bytes blanked, offsets kept.
func blankComments(lang lexctx.Lang, raw []byte) string {
	out := []byte(string(raw))
	for _, r := range lexctx.Classify(lang, raw) {
		if r.Kind != lexctx.KindComment {
			continue
		}
		for i := r.Start; i < r.End; i++ {
			if out[i] != '\n' {
				out[i] = ' '
			}
		}
	}
	return string(out)
}
