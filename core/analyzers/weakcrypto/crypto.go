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
package weakcrypto

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

// Analyzer reports use of broken or deprecated cryptographic primitives.
type Analyzer struct{}

// NewAnalyzer constructs the crypto analyzer.
func NewAnalyzer() *Analyzer { return &Analyzer{} }

// ruleID is the single rule this analyzer emits.
const ruleID = "CRYPTO-001"

// weakByExt matches construction of a broken primitive, per language.
//
// Each pattern targets the CONSTRUCTOR rather than the bare algorithm name, so
// a comment, a variable called `md5sum`, or a string in documentation does not
// match. That precision is the difference between a rule people keep and one
// they suppress.
var weakByExt = map[string]*regexp.Regexp{
	// crypto/md5, crypto/sha1, crypto/des, golang.org/x/crypto/rc4
	".go": regexp.MustCompile(`\b(md5|sha1|des|rc4)\.New(?:Cipher)?\(`),
	// hashlib.md5(...) / hashlib.sha1(...); also the Crypto.Cipher DES/ARC4 forms
	".py": regexp.MustCompile(`\bhashlib\.(md5|sha1)\(|\b(DES|ARC4)\.new\(`),
	// node: crypto.createHash('md5'), createCipheriv('des-...'/'rc4')
	".js": regexp.MustCompile(`createHash\(\s*['"](md5|sha1)['"]|createCipheriv\(\s*['"](des|rc4)`),
	".ts": regexp.MustCompile(`createHash\(\s*['"](md5|sha1)['"]|createCipheriv\(\s*['"](des|rc4)`),
	// MessageDigest.getInstance("MD5"), Cipher.getInstance("DES/...")
	".java": regexp.MustCompile(`(?:MessageDigest|Cipher)\.getInstance\(\s*"(MD5|SHA-?1|DES|RC4)`),
}

// algoNames extracts a human-readable algorithm from a match, for the message.
var algoNames = regexp.MustCompile(`(?i)\b(md5|sha-?1|des|rc4|arc4)\b`)

// Rules returns the rule this analyzer can emit, for the rule catalogue.
func (a *Analyzer) Rules() *rules.RuleSet {
	rs := rules.NewRuleSet()
	rs.Add(&rules.Rule{
		ID:          ruleID,
		Version:     "1.0",
		Description: "Broken or deprecated cryptographic primitive (MD5, SHA-1, DES, RC4)",
		Severity:    findings.SeverityMedium,
		// Low: the call site is unambiguous, but whether it is a VULNERABILITY
		// depends on what the digest is used for, which this cannot see.
		Confidence: findings.ConfidenceLow,
		Tags:       []string{"crypto", "weak-algorithm", "owasp-a02"},
		Remediation: "This constructs a primitive that is broken for security purposes: MD5 and SHA-1 are not collision-resistant, and DES and RC4 are not safe ciphers. " +
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
		if isTestPath(art.Path) {
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

		lineComment := lineCommentFor(ext)

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
			if c := strings.Index(line, lineComment); lineComment != "" && c >= 0 && c < loc[0] {
				continue
			}
			algo := "a broken primitive"
			if m := algoNames.FindString(line[loc[0]:loc[1]]); m != "" {
				algo = strings.ToUpper(m)
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

// lineCommentFor returns the line-comment marker for an extension, or "" when
// the language is not one this analyzer handles.
func lineCommentFor(ext string) string {
	switch ext {
	case ".go", ".js", ".ts", ".java":
		return "//"
	case ".py":
		return "#"
	default:
		return ""
	}
}

// isTestPath reports whether a path is test code, across the languages above.
func isTestPath(p string) bool {
	base := strings.ToLower(filepath.Base(p))
	if strings.HasSuffix(base, "_test.go") || strings.HasSuffix(base, ".test.js") ||
		strings.HasSuffix(base, ".test.ts") || strings.HasSuffix(base, ".spec.js") ||
		strings.HasSuffix(base, ".spec.ts") {
		return true
	}
	if strings.HasPrefix(base, "test_") && strings.HasSuffix(base, ".py") {
		return true
	}
	lower := strings.ToLower(p)
	return strings.Contains(lower, "/testdata/") || strings.Contains(lower, "/__tests__/")
}
