package secrets

import (
	"hash/crc32"
	"strings"

	"github.com/nox-hq/nox/core/lexctx"
)

// This file establishes something about a matched value that a regex cannot:
// whether it is internally consistent as a credential.
//
// # Why this is different in kind from everything else here
//
// Every other check the secrets analyzer performs is a heuristic. A pattern
// matched; a value did not look like a placeholder; the entropy was above a
// threshold. Each is worth doing and none of them establishes anything — a
// random 36-character string with the right prefix satisfies all of them.
//
// A checksum does not. GitHub's token formats carry a CRC32 of the token body,
// base62-encoded, in their last six characters. Recomputing it is deterministic
// static analysis in the kernel's exact sense of the phrase, so a verified
// token earns KindStatic rather than KindHeuristic — and that is the first
// thing in the secrets pipeline that legitimately does.
//
// # How the algorithm was established
//
// Not by inference. The format is documented publicly (GitHub's "Behind
// GitHub's new authentication token formats"), and the implementation here was
// checked against two independently published expired tokens BEFORE it was
// written into the analyzer. Both verify under CRC32-IEEE and neither under
// Castagnoli, which is what distinguishes a confirmed algorithm from a
// plausible one: the odds of two 6-character base62 checksums agreeing by
// chance are about one in 10^21.
//
// The care is not pedantry. A checksum implementation that is subtly wrong
// records FALSE DETERMINISTIC claims — it would tell the ledger that nox
// established something it got wrong, at a strength nothing else in the
// pipeline can reach. That is strictly worse than the silence it replaces,
// which is why this was verified first and built second.

// base62Alphabet is GitHub's, most-significant digit first.
const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// githubTokenPrefixes are the formats that carry a checksum. Each is followed
// by 30 body characters and 6 checksum characters.
var githubTokenPrefixes = []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"}

const (
	githubBodyLen     = 30
	githubChecksumLen = 6
)

// encodeBase62 renders n in GitHub's base62, left-padded with zeros to width.
func encodeBase62(n uint32, width int) string {
	if n == 0 {
		return strings.Repeat("0", width)
	}
	buf := make([]byte, 0, width)
	for n > 0 {
		buf = append([]byte{base62Alphabet[n%62]}, buf...)
		n /= 62
	}
	for len(buf) < width {
		buf = append([]byte{'0'}, buf...)
	}
	return string(buf)
}

// verifyGitHubToken reports whether value is a GitHub-format token whose
// checksum is consistent, and whether the check APPLIED at all.
//
// The second return is what keeps this honest. A value this cannot check —
// anything that is not a GitHub prefix followed by exactly 36 characters — must
// produce no claim in either direction, because "I cannot check this" and "I
// checked this and it failed" are different statements and only the second is
// evidence. Collapsing them is the mistake the whole capability model exists
// to prevent, and it would be an easy one to make in a function returning a
// single bool.
func verifyGitHubToken(value string) (consistent, applicable bool) {
	v := strings.Trim(value, `"'`)
	for _, prefix := range githubTokenPrefixes {
		if !strings.HasPrefix(v, prefix) {
			continue
		}
		rest := v[len(prefix):]
		if len(rest) != githubBodyLen+githubChecksumLen {
			return false, false
		}
		body := rest[:githubBodyLen]
		want := rest[githubBodyLen:]
		if !onlyBase62(body) || !onlyBase62(want) {
			return false, false
		}
		return encodeBase62(crc32.ChecksumIEEE([]byte(body)), githubChecksumLen) == want, true
	}
	return false, false
}

// onlyBase62 reports whether s is entirely base62 characters. A token
// containing anything else is not one this check can speak about.
func onlyBase62(s string) bool {
	for i := range len(s) {
		if !strings.ContainsRune(base62Alphabet, rune(s[i])) {
			return false
		}
	}
	return s != ""
}

// verifyJWT reports whether value is a structurally valid JSON Web Token, and
// whether the check APPLIED.
//
// It is the second deterministic signal in this pipeline, after the GitHub
// checksum. A JWT is three base64url segments separated by dots, and the first
// — the header — decodes to a JSON object naming a signing algorithm. That is
// offline-verifiable: no network, no key. It does not check the SIGNATURE,
// which needs the key nox does not have and must not want; it establishes that
// the value is a real JWT rather than a string that happens to match the loose
// `eyJ....eyJ....` pattern.
//
// The distinction matters because the pattern is weak. `eyJ` is `{"` in
// base64url, so any header starting `eyJ` decodes to something starting `{"` —
// but a full segment that is valid base64url AND decodes to a complete JSON
// object with an `alg` field is a much stronger statement, and its absence is a
// deterministic refutation rather than a heuristic doubt.
//
// Three-valued like the checksum: a value that is not three dot-separated
// segments is not something this can speak about (applicable=false), a value
// whose header decodes to a JSON object with `alg` is consistent, and one that
// looks like a JWT but whose header does not decode is deterministically not a
// JWT.
func verifyJWT(value string) (consistent, applicable bool) {
	if !lexctx.LooksJWTShaped(value) {
		// Not the shape of a JWT, so this check has nothing to say.
		return false, false
	}
	// Shaped like one; whether it IS one is the structural question lexctx
	// answers, and it answers it the same way for the data-blob refiner, so the
	// two cannot disagree about what a JWT is.
	return lexctx.LooksLikeJWT(value), true
}
