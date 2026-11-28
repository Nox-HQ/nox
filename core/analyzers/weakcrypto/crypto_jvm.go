package weakcrypto

import (
	"regexp"
	"strings"
)

// JVM weak primitives the literal pattern (jvmPattern) cannot see.
//
// JCA names every algorithm with a string, and jvmPattern reads it only when
// it is written inside the getInstance call. Two things escape it:
//
//   - The algorithm held in a name: `private static final String ALG =
//     "DES/CBC/PKCS5Padding"; ... Cipher.getInstance(ALG)`, a local assigned
//     once, or a configured value, `props.getProperty("cipher")` or
//     `props.getProperty("cipher", "DESede/ECB/PKCS5Padding")`. A configured
//     key is read from the project's .properties files; the fallback is what
//     runs only when no file defines the key, so it is used only then, and
//     only when the scan saw the project's properties files at all. The
//     constant is the commoner way to write it in application code.
//   - Weak forms jvmPattern does not list: MD2/MD4 and the bare "SHA" alias
//     of SHA-1; Blowfish (a 64-bit block, Sweet32); `Cipher.getInstance("AES")`,
//     which the JDK providers expand to AES/ECB/PKCS5Padding; DES-family key
//     generators and key factories; signatures over MD5 or SHA-1; Commons
//     Codec's and Guava's MD5/SHA-1 one-shot calls. RSA padding is not
//     judged here: "RSA/ECB/..." is a JCA misnomer, and PKCS#1 v1.5 is a
//     padding weakness, not a broken primitive (crypto_test.go pins it).
//
// This pass runs only on lines jvmPattern did not match, so a finding the
// literal pattern already makes keeps its message and its fingerprint.
//
// A name resolves only when the file assigns it exactly once, to a string
// literal or to a getProperty call whose key the project's .properties files
// define one way (or, when none defines it, whose literal fallback); anything
// else is unknown and reports nothing, the same refuse-rather-than-guess
// contract as the taint engine's constant evaluator.

// jvmGetInstance matches a JCA factory call and captures the factory and its
// first argument, either a string literal (group 2) or a simple name (group 3).
var jvmGetInstance = regexp.MustCompile(
	`\b(MessageDigest|Cipher|Signature|KeyGenerator|SecretKeyFactory)\s*\.\s*getInstance\s*\(\s*(?:"([^"\\]*)"|([A-Za-z_]\w*))\s*[,)]`)

// jvmOneShot matches library one-shot digests: Commons Codec's DigestUtils
// (md5, md5Hex, sha1, sha1Hex, and the deprecated sha/shaHex) and Guava's
// Hashing.md5()/sha1().
var jvmOneShot = regexp.MustCompile(
	`\bDigestUtils\s*\.\s*(md5|sha1|sha)(?:Hex)?\s*\(|\bHashing\s*\.\s*(md5|sha1)\s*\(`)

var (
	// jvmLiteralAssign: NAME = "literal" (Java, with or without a type and
	// modifiers; Kotlin val/var/const val).
	jvmLiteralAssign = regexp.MustCompile(`(?m)(?:^|[^\w.])([A-Za-z_]\w*)\s*(?::\s*String\s*)?=\s*"([^"\\]*)"\s*(?:;|$)`)
	// jvmPropertyAssign: NAME = props.getProperty("key"[, "fallback"]).
	jvmPropertyAssign = regexp.MustCompile(`(?m)(?:^|[^\w.])([A-Za-z_]\w*)\s*(?::\s*String\s*)?=\s*[A-Za-z_][\w.]*\s*\.\s*getProperty\s*\(\s*"([^"\\]*)"\s*(?:,\s*"([^"\\]*)"\s*)?\)\s*(?:;|$)`)
	// jvmAnyAssign counts every assignment to a name: `=` not part of `==`,
	// `!=`, `<=`, `>=`, and not a compound operator's tail.
	jvmAnyAssign = regexp.MustCompile(`(?:^|[^\w.])([A-Za-z_]\w*)\s*(?::\s*[\w.<>?]+\s*)?=(?:[^=]|$)`)
)

// jvmConstants maps each name the file assigns exactly once to the string it
// holds: a literal, or a getProperty call's configured value. props holds the
// project's properties (projectProperties); a key it defines decides, and the
// literal fallback is used only for a key it does not define. A key defined
// with different values in different files is unknown.
func jvmConstants(content string, props map[string]string) map[string]string {
	counts := map[string]int{}
	for _, m := range jvmAnyAssign.FindAllStringSubmatch(content, -1) {
		counts[m[1]]++
	}
	out := map[string]string{}
	for _, m := range jvmLiteralAssign.FindAllStringSubmatch(content, -1) {
		if counts[m[1]] == 1 {
			out[m[1]] = m[2]
		}
	}
	for _, m := range jvmPropertyAssign.FindAllStringSubmatchIndex(content, -1) {
		name := content[m[2]:m[3]]
		if counts[name] != 1 {
			continue
		}
		key := content[m[4]:m[5]]
		if v, defined := props[key]; defined {
			// A conflicting key holds propertyConflict, which names no
			// algorithm, so it reports nothing -- and, being defined, it
			// never falls through to the fallback.
			out[name] = v
			continue
		}
		// No file defines the key. The fallback runs then -- but only a scan
		// that sees the project's configuration knows that no file defines
		// it; one rooted below it (src/main/java) sees none, and the key may
		// well be set.
		if m[6] >= 0 && props[propertiesSeen] == "1" {
			out[name] = content[m[6]:m[7]]
		}
	}
	return out
}

// propertyConflict marks a key two properties files define differently.
const propertyConflict = "\x00conflict"

// propertiesSeen is set ("1") in the properties map when the scan read at
// least one .properties file; no real key contains a NUL.
const propertiesSeen = "\x00seen"

// propertyLine is a `key=value` or `key: value` line of a .properties file.
var propertyLine = regexp.MustCompile(`^\s*([^#!=:\s][^=:\s]*)\s*[=:]\s*(.*?)\s*$`)

// parseProperties adds the keys of one .properties file to into. A key
// defined with a different value than an earlier file gave it becomes a
// conflict. Continuation lines and escapes are not interpreted: a value that
// uses them is read as written, which only ever makes it match less.
func parseProperties(content []byte, into map[string]string) {
	for _, line := range strings.Split(string(content), "\n") {
		m := propertyLine.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if m == nil {
			continue
		}
		if prev, seen := into[m[1]]; seen && prev != m[2] {
			into[m[1]] = propertyConflict
			continue
		}
		into[m[1]] = m[2]
	}
}

// jvmWeakAlgorithm names the weakness of factory used with algorithm alg, or
// returns "" when the combination is not weak.
func jvmWeakAlgorithm(factory, alg string) string {
	parts := strings.Split(strings.ToUpper(strings.TrimSpace(alg)), "/")
	base := parts[0]
	mode := ""
	if len(parts) > 1 {
		mode = parts[1]
	}
	switch factory {
	case "MessageDigest":
		switch base {
		case "MD2", "MD4", "MD5":
			return base
		case "SHA", "SHA1", "SHA-1":
			return "SHA-1"
		}
	case "Signature":
		for _, d := range []struct{ prefix, name string }{{"MD2WITH", "MD2"}, {"MD5WITH", "MD5"}, {"SHA1WITH", "SHA-1"}} {
			if strings.HasPrefix(base, d.prefix) {
				return d.name
			}
		}
	case "Cipher":
		if name := weakCipherBase(base); name != "" {
			return name
		}
		// The JDK providers expand a bare "AES" to AES/ECB/PKCS5Padding.
		if base == "AES" && (mode == "" || mode == "ECB") {
			return "ECB"
		}
	case "KeyGenerator", "SecretKeyFactory":
		if name := weakCipherBase(base); name != "" {
			return name
		}
		if strings.HasPrefix(base, "PBEWITHMD5") {
			return "MD5"
		}
		if strings.HasPrefix(base, "PBEWITHSHA1ANDDES") || strings.HasPrefix(base, "PBEWITHSHA1ANDRC") {
			return "SHA-1"
		}
	}
	return ""
}

// weakCipherBase names a broken symmetric cipher family, or "".
func weakCipherBase(base string) string {
	switch base {
	case "DES":
		return "DES"
	case "DESEDE", "TRIPLEDES", "3DES":
		return "3DES"
	case "RC2":
		return "RC2"
	case "RC4", "ARCFOUR", "ARC4":
		return "RC4"
	case "BLOWFISH":
		return "Blowfish"
	}
	return ""
}

// jvmLineWeakness reports the weak primitive a JVM line uses that jvmPattern
// does not match, resolving a named algorithm through consts.
func jvmLineWeakness(line string, consts map[string]string) (algo string, at int) {
	for _, m := range jvmGetInstance.FindAllStringSubmatchIndex(line, -1) {
		factory := line[m[2]:m[3]]
		var alg string
		switch {
		case m[4] >= 0:
			alg = line[m[4]:m[5]]
		case m[6] >= 0:
			v, ok := consts[line[m[6]:m[7]]]
			if !ok {
				continue
			}
			alg = v
		}
		if name := jvmWeakAlgorithm(factory, alg); name != "" {
			return name, m[0]
		}
	}
	if m := jvmOneShot.FindStringSubmatchIndex(line); m != nil {
		fn := ""
		for g := 2; g+1 < len(m); g += 2 {
			if m[g] >= 0 {
				fn = line[m[g]:m[g+1]]
			}
		}
		if strings.EqualFold(fn, "md5") {
			return "MD5", m[0]
		}
		return "SHA-1", m[0]
	}
	return "", -1
}
