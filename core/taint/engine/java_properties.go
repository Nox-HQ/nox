package engine

import (
	"regexp"
	"strings"
)

// System.getProperty is a Java taint source because a property can be set on
// the command line (-Dkey=value) by whoever launches the JVM. The standard
// properties the JVM itself defines are not that: `user.dir`, `os.name`,
// `java.io.tmpdir` and `line.separator` describe the machine, and no request
// can change them. Treating them as untrusted reported
// `new File(System.getProperty("user.dir"))` inside an exec call as command
// injection -- 38 of the OWASP Benchmark for Java's false positives.
//
// The key is a string literal, which the code view blanks, so the catalog
// cannot tell one call from another. The extractor does: a call whose literal
// key names a standard property is renamed, in both views and at the same
// offsets, to System.jvmProperty -- the same length, and not a source. Any
// other key, and any key that is not a literal, stays a source.

var javaStdPropertyCall = regexp.MustCompile(`\bSystem\s*\.\s*getProperty\s*\(\s*"([^"]*)"`)

// javaStandardProperties are the keys the JVM defines itself (the
// System.getProperties contract), by exact name or by prefix.
var javaStandardProperties = []string{
	"java.", "os.", "file.separator", "path.separator", "line.separator",
	"user.name", "user.home", "user.dir", "user.country", "user.language",
	"user.timezone", "native.encoding", "stdout.encoding", "stderr.encoding",
	"file.encoding", "sun.",
}

func isStandardJVMProperty(key string) bool {
	for _, p := range javaStandardProperties {
		if key == p || strings.HasSuffix(p, ".") && strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

// neutralizeStandardProperties renames System.getProperty calls on standard
// JVM keys so they are not read as a taint source.
func neutralizeStandardProperties(lines []logicalLine) {
	for i := range lines {
		ll := &lines[i]
		if !strings.Contains(ll.raw, "getProperty") {
			continue
		}
		for _, m := range javaStdPropertyCall.FindAllStringSubmatchIndex(ll.raw, -1) {
			if !isStandardJVMProperty(ll.raw[m[2]:m[3]]) {
				continue
			}
			at := strings.Index(ll.raw[m[0]:m[1]], "getProperty") + m[0]
			if at+len("getProperty") > len(ll.code) || ll.code[at:at+len("getProperty")] != "getProperty" {
				continue // views not aligned here: leave the source as it was
			}
			ll.raw = ll.raw[:at] + "jvmProperty" + ll.raw[at+len("getProperty"):]
			ll.code = ll.code[:at] + "jvmProperty" + ll.code[at+len("getProperty"):]
		}
	}
}
