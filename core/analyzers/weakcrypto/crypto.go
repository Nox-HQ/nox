// Package weakcrypto detects use of broken or deprecated cryptographic primitives.
//
// WHY THIS IS ITS OWN ANALYZER. Core's other analyzers do not have a home for
// this. It is not a taint flow — MD5 is unsafe for a digest regardless of where
// its input came from, so there is no source to track. It is not a secret, so
// the secrets analyzer is wrong. It is dangerous *API usage*, which nothing in
// core previously modelled.
//
// It replaces SAST-007 from the nox-plugin-sast plugin, which is being retired:
// seven of that plugin's nine rules duplicated core's taint engine under a
// second rule-ID namespace, so the same vulnerability was reported twice. Weak
// crypto and open redirect were the only genuinely additive rules; open
// redirect moved into the taint catalogue (where it can be taint-gated), and
// this is the other half.
//
// SCOPE, deliberately narrow. Only primitives that are broken for *security*
// purposes are flagged, and only where the call is unambiguous. MD5 and SHA-1
// remain legitimate for non-security work — cache keys, ETags, content
// addressing, checksums against accidental corruption — so this analyzer
// reports Medium at Low confidence and says so in the remediation, rather than
// pretending every occurrence is a vulnerability. Over-flagging a ubiquitous
// stdlib call is how a rule gets globally suppressed, which costs more than the
// rule is worth.
//
// TWO CALL SHAPES, NOT ONE. Every language here exposes a digest both as a
// streaming constructor (md5.New(), MD5_Init(), MD5.Create()) and as a one-shot
// convenience call (md5.Sum(b), MD5(b, n, out), MD5.HashData(b)). The one-shot
// form is usually the *more* idiomatic of the two, so a pattern that knows only
// the constructor misses the commoner usage. The patterns below cover both
// shapes wherever a language offers both.
//
// LANGUAGE ISOLATION. Patterns are keyed by extension and are never shared
// across languages that do not share syntax. This matters: `Digest::MD5` is a
// Ruby constant path, `md5::compute` is a Rust path, and `MD5(` is an OpenSSL C
// function — applying any one of them to the other two languages would
// manufacture matches out of unrelated syntax. The `languages` table below is
// the single source of truth binding a pattern, its extensions, and its comment
// markers together, so an extension cannot silently acquire another language's
// pattern.
package weakcrypto

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/source"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// Analyzer reports use of broken or deprecated cryptographic primitives.
type Analyzer struct{}

// NewAnalyzer constructs the crypto analyzer.
func NewAnalyzer() *Analyzer { return &Analyzer{} }

// ruleID is the single rule this analyzer emits.
const ruleID = "CRYPTO-001"

// language binds one language's detection pattern to the file extensions it may
// be applied to and the line-comment markers used to suppress commented-out
// code. Keeping the three together is deliberate: a pattern written for one
// language's syntax must never become reachable from another language's files.
type language struct {
	// name is the canonical language name, matching core's SAST language set.
	name string
	// exts are the lowercased file extensions this pattern applies to.
	exts []string
	// pattern matches construction *or* one-shot invocation of a primitive that
	// is broken for security purposes.
	pattern *regexp.Regexp
	// comments are the line-comment markers for the language. A match sitting
	// to the right of one is ignored.
	comments []string
}

// jsPattern is shared by JavaScript and TypeScript, which reach the same
// node:crypto and CryptoJS APIs with identical syntax.
var jsPattern = regexp.MustCompile(
	`\bcreateHash\s*\(\s*['"](?i:md5|sha-?1)['"]` +
		`|\bcreate(?:De)?[Cc]ipheriv\s*\(\s*['"](?i:des|rc4|rc2|[a-z0-9-]*-ecb)` +
		`|\bCryptoJS\.(?:MD5|SHA1|DES|TripleDES|RC4)\b`)

// jvmPattern is shared by Java and Kotlin, which call the same JCA factories.
// JCA is entirely string-named, so the algorithm is a literal argument to
// getInstance; ECB is named inside the transformation string
// ("AES/ECB/PKCS5Padding"), which is why it needs its own alternative.
//
// The ECB alternative is restricted to symmetric ciphers by name. JCA calls RSA
// padding modes "ECB" as a historical misnomer, so the extremely common and
// entirely correct `Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")`
// must not match — a rule that flags correct OAEP would be turned off within a
// day.
var jvmPattern = regexp.MustCompile(
	// "DES" is left to prefix-match "DESede" rather than being listed
	// separately: the matched text is what the reported algorithm name is
	// scraped from, and lengthening the match would rename an existing finding,
	// which changes its fingerprint and silently invalidates baselines.
	`\b(?:MessageDigest|Cipher|Signature)\.getInstance\s*\(\s*"(?i:MD5|SHA-?1|DES|RC4|RC2|ARCFOUR)` +
		`|\bCipher\.getInstance\s*\(\s*"(?i:AES|DES|3DES|Blowfish|RC2|RC4)[^"]*/ECB/`)

// cPattern is shared by C, C++ and Objective-C, which reach the same OpenSSL
// and CommonCrypto entry points. It covers both call shapes: the streaming
// _Init/_Update/_Final trio and the one-shot MD5(d, n, out) form.
//
// The bare one-shot form is bounded twice over. The parenthesis must touch the
// name — `MD5 (` with a space is far more likely to be prose in a string
// literal, since OpenSSL's own dgst output is `MD5 (file) = …` and a printf of
// that format string is not a finding. And the name must not be preceded by a
// dot, so a member call such as `obj.MD5(x)` (or another language's
// `CryptoJS.MD5(x)`, should such a line ever reach a C file) stays out.
var cPattern = regexp.MustCompile(
	`\b(?:MD5|SHA1|MD4)_(?:Init|Update|Final)\s*\(` +
		`|(?:^|[^A-Za-z0-9_.])(?:MD5|SHA1|MD4)\(` +
		`|\bCC_(?:MD5|SHA1)(?:_Init|_Update|_Final)?\s*\(` +
		`|\bEVP_(?:md5|md4|sha1)\s*\(` +
		`|\bEVP_(?:des|rc4|rc2)[a-z0-9_]*\s*\(` +
		`|\bEVP_[a-z0-9_]*_ecb\s*\(` +
		`|\bDES_(?:set_key[a-z_]*|key_sched|ecb[0-9]?_encrypt|ncbc_encrypt|cbc_encrypt|ede3_cbc_encrypt)\s*\(` +
		`|\bRC4_set_key\s*\(|(?:^|[^A-Za-z0-9_.])RC4\(` +
		`|\bkCCAlgorithm(?:DES|3DES|RC4|RC2)\b` +
		`|\bkCCOptionECBMode\b`)

// languages holds one entry per language core's SAST supports. Two entries —
// PHP and shell — are deliberately narrower than the language's full weak-crypto
// surface; each says why in place.
//
// Each pattern targets a CALL or a package-qualified symbol rather than the
// bare algorithm name, so a comment, a variable called `md5sum`, or a string in
// documentation does not match. That precision is the difference between a rule
// people keep and one they suppress.
var languages = []language{
	{
		name: "go",
		exts: []string{".go"},
		// crypto/md5 and crypto/sha1 expose both New() (streaming) and Sum()
		// (one-shot); crypto/des and golang.org/x/crypto/rc4 expose cipher
		// constructors. Go's stdlib has no ECB mode, so there is nothing to
		// match for it here.
		pattern: regexp.MustCompile(
			`\b(?:md5|sha1)\.(?:New|Sum)\s*\(` +
				`|\b(?:des|rc4)\.New(?:Cipher|TripleDESCipher)\s*\(`),
		comments: []string{"//"},
	},
	{
		name: "python",
		exts: []string{".py"},
		// hashlib's direct constructors and its string-named new() form;
		// PyCryptodome's DES/DES3/ARC4 ciphers; and the `cryptography`
		// package's explicit ECB mode and legacy algorithm classes.
		pattern: regexp.MustCompile(
			`\bhashlib\.(?:md5|sha1)\s*\(` +
				`|\bhashlib\.new\s*\(\s*['"](?i:md5|sha-?1)['"]` +
				`|\b(?:DES|DES3|ARC2|ARC4)\.new\s*\(` +
				`|\bmodes\.ECB\s*\(` +
				`|\balgorithms\.(?:TripleDES|ARC4)\s*\(`),
		comments: []string{"#"},
	},
	{
		name: "javascript",
		exts: []string{".js", ".jsx", ".mjs", ".cjs"},
		// A URL inside a string ("http://…") is indexed as a comment start by
		// the marker scan below. That can only ever suppress a match, never
		// create one, so it is an accepted false negative rather than noise.
		pattern:  jsPattern,
		comments: []string{"//"},
	},
	{
		name:     "typescript",
		exts:     []string{".ts", ".tsx", ".mts", ".cts"},
		pattern:  jsPattern,
		comments: []string{"//"},
	},
	{
		name:     "java",
		exts:     []string{".java"},
		pattern:  jvmPattern,
		comments: []string{"//"},
	},
	{
		name: "kotlin",
		exts: []string{".kt"},
		// Kotlin calls the same JCA API with the same string literals.
		pattern:  jvmPattern,
		comments: []string{"//"},
	},
	{
		name: "php",
		exts: []string{".php"},
		// DELIBERATELY EXCLUDES BARE md5() AND sha1(). They are global
		// functions, they are among the most-called functions in the language,
		// and the overwhelming majority of calls are cache keys, ETags,
		// Gravatar hashes (which the Gravatar protocol *requires* to be MD5),
		// asset fingerprints and array keys. Flagging them would put findings
		// in essentially every PHP file in existence — precisely the
		// "ubiquitous stdlib call" the scope note above forbids. The rule would
		// be globally disabled, and the genuinely broken cipher usage below
		// would be disabled with it. What is kept is the subset that is
		// unambiguously security-bearing: the encryption and digest APIs, where
		// there is no benign "checksum" reading of DES, RC4 or ECB.
		pattern: regexp.MustCompile(
			`\bmcrypt_[a-z_]+\s*\(` +
				`|\bMCRYPT_(?:DES|3DES|TRIPLEDES|RC4|RC2|ARCFOUR)\b` +
				`|\bopenssl_(?:encrypt|decrypt)\s*\([^,]*,\s*['"](?i:des|rc4|rc2|[a-z0-9-]*-ecb)` +
				`|\bopenssl_digest\s*\([^,]*,\s*['"](?i:md5|sha-?1)['"]`),
		comments: []string{"//", "#"},
	},
	{
		name: "ruby",
		exts: []string{".rb"},
		// Digest::MD5 is a constant path, not a bare word, so it cannot be
		// confused with a local variable named md5. OpenSSL::Cipher takes its
		// cipher either as a constant or as an OpenSSL cipher string.
		pattern: regexp.MustCompile(
			`\b(?:OpenSSL::)?Digest::(?:MD5|SHA1)\b` +
				`|\bOpenSSL::Digest\.new\s*\(\s*['"](?i:md5|sha-?1)['"]` +
				`|\bOpenSSL::Cipher::(?:DES|RC4|RC2)\b` +
				`|\bOpenSSL::Cipher(?:::[A-Za-z0-9]+)?\.new\s*\(\s*['"](?i:des|rc4|rc2|[a-z0-9-]*-ecb)` +
				`|\bOpenSSL::Cipher::[A-Za-z0-9]+\.new\s*\([^)]*:ECB\b`),
		comments: []string{"#"},
	},
	{
		name: "csharp",
		exts: []string{".cs"},
		// System.Security.Cryptography exposes each algorithm as a class with a
		// static Create()/HashData() factory, plus the legacy
		// *CryptoServiceProvider / *Managed / *Cng implementation types.
		pattern: regexp.MustCompile(
			`\b(?:MD5|SHA1|DES|TripleDES|RC2)\.(?:Create|HashData)\s*\(` +
				`|\b(?:MD5|SHA1|DES|TripleDES|RC2)(?:CryptoServiceProvider|Managed|Cng)\b` +
				`|\b(?:HashAlgorithm|CryptoConfig|SymmetricAlgorithm)\.Create\s*\(\s*"(?i:md5|sha-?1|des|tripledes|rc2)` +
				`|\bCipherMode\.ECB\b`),
		comments: []string{"//"},
	},
	{
		name: "rust",
		exts: []string{".rs"},
		// The `md5` crate's one-shot compute(), the RustCrypto Digest types,
		// the legacy block ciphers, and the `ecb` mode wrapper. `Md5::new()` is
		// a path-qualified associated function, so a local named md5 does not
		// match.
		pattern: regexp.MustCompile(
			`\bmd5::compute\s*\(` +
				`|\b(?:Md5|Sha1|Md4)::(?:new|new_with_prefix|default|digest)\s*\(` +
				`|\b(?:Des|TdesEde3|TdesEde2|Rc4|Rc2)::new\s*\(` +
				`|\becb::(?:Encryptor|Decryptor)\b`),
		comments: []string{"//"},
	},
	{
		name: "c",
		exts: []string{".c", ".h"},
		// Headers stay on the C pattern even in Objective-C and C++ projects:
		// it is the superset (OpenSSL plus CommonCrypto) and the dialects share
		// the same dangerous API surface.
		pattern:  cPattern,
		comments: []string{"//"},
	},
	{
		name:     "cpp",
		exts:     []string{".cpp", ".cc", ".cxx", ".c++", ".hpp", ".hh", ".hxx", ".ipp", ".inl"},
		pattern:  cPattern,
		comments: []string{"//"},
	},
	{
		name: "objc",
		exts: []string{".m", ".mm"},
		// `.m` is also MATLAB's extension. That is safe here only because every
		// alternative in cPattern is an Apple CommonCrypto or OpenSSL
		// identifier that does not occur in MATLAB — which is exactly why
		// patterns are bound per extension rather than pooled.
		pattern:  cPattern,
		comments: []string{"//"},
	},
	{
		name: "swift",
		exts: []string{".swift"},
		// CryptoKit puts the broken digests behind an `Insecure` namespace, so
		// `Insecure.MD5` is both unambiguous and self-documenting. Bridged
		// CommonCrypto is still widely used and is matched too.
		pattern: regexp.MustCompile(
			`\bInsecure\.(?:MD5|SHA1)\b` +
				`|\bCC_(?:MD5|SHA1)(?:_Init|_Update|_Final)?\s*\(` +
				`|\bkCCAlgorithm(?:DES|3DES|RC4|RC2)\b` +
				`|\bkCCOptionECBMode\b`),
		comments: []string{"//"},
	},
	{
		name: "shell",
		exts: []string{".sh"},
		// DELIBERATELY EXCLUDES md5sum, sha1sum AND shasum. In shell those
		// commands are almost never a security control: they verify a download
		// against accidental corruption, fingerprint a build artifact, or key a
		// cache. Flagging them would bury every Makefile-adjacent script in
		// findings for a checksum that was never claimed to be
		// collision-resistant. The security-bearing case in shell is `openssl
		// enc` (or the legacy `openssl des3`/`openssl rc4` subcommands) with a
		// broken cipher, which is unambiguous, so that is all this matches.
		pattern: regexp.MustCompile(
			`\bopenssl\s+enc\b[^\n]*\s-(?:des|des3|desx|rc4|rc2|[a-z0-9-]*-ecb)\b` +
				`|\bopenssl\s+(?:des3|des-ede3|rc4)\b`),
		comments: []string{"#"},
	},
}

// weakByExt indexes the language table by extension. It is built once from
// `languages` so an extension can never be bound to a pattern written for a
// language it does not belong to.
var weakByExt = func() map[string]*regexp.Regexp {
	m := make(map[string]*regexp.Regexp, len(languages)*3)
	for _, l := range languages {
		for _, e := range l.exts {
			m[e] = l.pattern
		}
	}
	return m
}()

// commentsByExt indexes the line-comment markers by extension, from the same
// table.
var commentsByExt = func() map[string][]string {
	m := make(map[string][]string, len(languages)*3)
	for _, l := range languages {
		for _, e := range l.exts {
			m[e] = l.comments
		}
	}
	return m
}()

// algoAlternatives lists the algorithm names reported in a finding's message
// and `algorithm` metadata. Longer names precede their own prefixes so
// `TripleDES` does not report as `DES`.
const algoAlternatives = `3des|des3|desede|tdesede[23]|tripledes|des|md5|md4|sha-?1|rc4|rc2|arc4|arcfour|ecb`

// algoSeparated finds an algorithm delimited by non-alphanumerics or by a
// CamelCase boundary on the right. Plain `\b` is not enough here: `_` is a word
// character, so `\bmd5\b` never matches `MD5_Init` or `CC_MD5`, and the
// analyzer used to fall back to the placeholder name for most C findings.
var algoSeparated = regexp.MustCompile(
	`(?:^|[^A-Za-z0-9])((?i:` + algoAlternatives + `))(?:[^A-Za-z0-9]|[A-Z]|$)`)

// algoCamel is the fallback for identifiers with no separator at all, where the
// only boundary is the case transition: `kCCAlgorithmDES`, `kCCOptionECBMode`.
// It is case-sensitive by design — requiring the algorithm in upper case is
// what keeps it from reading `des` out of the middle of an ordinary lowercase
// word such as `modes`.
var algoCamel = regexp.MustCompile(
	`[a-z](3DES|DES3|DESede|TripleDES|DES|MD5|MD4|SHA-?1|RC4|RC2|ARC4|ARCFOUR|ECB)(?:[^a-z0-9]|[A-Z]|$)`)

// algorithmIn names the primitive a matched call uses, or "" when the match
// carries no recognisable algorithm name.
func algorithmIn(match string) string {
	for _, re := range []*regexp.Regexp{algoSeparated, algoCamel} {
		if m := re.FindStringSubmatch(match); m != nil {
			return strings.ToUpper(m[1])
		}
	}
	return ""
}

// Rules returns the rule this analyzer can emit, for the rule catalogue.
func (a *Analyzer) Rules() *rules.RuleSet {
	rs := rules.NewRuleSet()
	rs.Add(&rules.Rule{
		ID:          ruleID,
		Version:     "1.0",
		Description: "Broken or deprecated cryptographic primitive (MD5, SHA-1, DES, 3DES, RC4, ECB mode)",
		Severity:    findings.SeverityMedium,
		// Low: the call site is unambiguous, but whether it is a VULNERABILITY
		// depends on what the digest is used for, which this cannot see.
		Confidence: findings.ConfidenceLow,
		Tags:       []string{"crypto", "weak-algorithm", "owasp-a02"},
		Remediation: "This constructs or invokes a primitive that is broken for security purposes: MD5 and SHA-1 are not collision-resistant, DES, 3DES and RC4 are not safe ciphers, and ECB mode leaks plaintext structure. " +
			"If this value is used for authentication, signatures, password storage, integrity against a motivated attacker, or anything else security-bearing, replace it — SHA-256 or better for digests, AES-GCM or ChaCha20-Poly1305 for encryption, and a dedicated KDF (Argon2id, scrypt, bcrypt) for passwords. " +
			"If it is used for a non-security purpose such as a cache key, an ETag, content addressing, or a checksum against accidental corruption, MD5 and SHA-1 are acceptable and this finding can be suppressed with a nox:ignore comment recording that reason.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/327.html",
			"https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
		},
		Metadata: map[string]string{"cwe": "CWE-327"},
	})
	rs.Add(randRule())
	return rs
}

// ScanArtifacts reports weak-primitive construction across discovered sources.
func (a *Analyzer) ScanArtifacts(ctx context.Context, artifacts []discovery.Artifact) (*findings.FindingSet, error) {
	fs := findings.NewFindingSet()

	for _, art := range artifacts {
		if err := ctx.Err(); err != nil {
			return fs, err
		}
		ext := strings.ToLower(filepath.Ext(art.Path))
		re, weakOK := weakByExt[ext]
		// Insecure randomness (CRYPTO-002) is Go-only; see rand.go.
		randOK := ext == ".go"
		if !weakOK && !randOK {
			continue
		}
		// Test files are skipped: fixtures deliberately exercise weak
		// primitives (including this analyzer's own tests), and flagging them
		// is noise that trains people to ignore the rule. The same holds for
		// predictable randomness, where determinism in a test is a feature.
		if source.IsTestPath(art.Path) {
			continue
		}

		content, err := os.ReadFile(art.AbsPath)
		if err != nil {
			// Unreadable file is not a finding; discovery already surfaced it.
			continue
		}

		if randOK {
			scanInsecureRandom(fs, art, content)
		}
		if !weakOK {
			continue
		}

		markers := commentsByExt[ext]

		for i, line := range strings.Split(string(content), "\n") {
			loc := re.FindStringIndex(line)
			if loc == nil {
				continue
			}
			// Skip a match that sits inside a line comment. Commented-out or
			// historical code frequently contains the literal call syntax
			// ("// createHash('md5') is no longer used"), and flagging it is
			// the kind of noise that gets a rule globally suppressed.
			//
			// Line comments only: block comments and string literals are not
			// tracked, since doing so properly needs a parser per language and
			// the residual false-positive rate is low enough to accept.
			if inLineComment(line, markers, loc[0]) {
				continue
			}
			algo := "a broken primitive"
			if m := algorithmIn(line[loc[0]:loc[1]]); m != "" {
				algo = m
			}
			fs.Add(findings.Finding{
				RuleID:   ruleID,
				Severity: findings.SeverityMedium,
				// Confidence mirrors the rule: unambiguous call, ambiguous purpose.
				Confidence: findings.ConfidenceLow,
				Message:    "Use of " + algo + ", which is broken for security purposes",
				Location: findings.Location{
					FilePath:  art.Path,
					StartLine: i + 1,
					EndLine:   i + 1,
				},
				Metadata: map[string]string{"cwe": "CWE-327", "algorithm": algo},
			})
		}
	}
	return fs, nil
}

// inLineComment reports whether a match starting at `at` sits to the right of a
// line-comment marker. Languages with more than one marker (PHP accepts both
// `//` and `#`) are checked against all of theirs.
func inLineComment(line string, markers []string, at int) bool {
	for _, m := range markers {
		if m == "" {
			continue
		}
		if c := strings.Index(line, m); c >= 0 && c < at {
			return true
		}
	}
	return false
}
