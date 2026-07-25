package lexctx

import "testing"

// TestConfigLangString pins the stable lowercase labels used in metadata.
func TestConfigLangString(t *testing.T) {
	if got := LangYAML.String(); got != "yaml" {
		t.Errorf("LangYAML.String() = %q, want %q", got, "yaml")
	}
	if got := LangDockerfile.String(); got != "dockerfile" {
		t.Errorf("LangDockerfile.String() = %q, want %q", got, "dockerfile")
	}
}

// TestScanYAMLComment: a YAML `#` inline comment (preceded by whitespace) is a
// comment; the following mapping value stays code, and a `#` inside a quoted
// scalar stays string. These are the exact roles the absence matcher depends
// on to know a keyword mentioned only in a comment cannot satisfy a rule.
func TestScanYAMLComment(t *testing.T) {
	src := "on: [push]\n" +
		"name: build # attested elsewhere\n" +
		"tag: \"v1 # not a comment\"\n" +
		"note: 'single # kept'\n"
	cases := []struct {
		needle string
		want   Kind
	}{
		{"on: [push]", KindCode},
		{"attested elsewhere", KindComment},
		{`"v1 # not a comment"`, KindString},
		{`'single # kept'`, KindString},
	}
	for _, c := range cases {
		if k := kindOfSubstring(t, LangYAML, src, c.needle); k != c.want {
			t.Errorf("needle %q: got %v, want %v", c.needle, k, c.want)
		}
	}
}

// TestScanDockerfileComment: a full-line `#` comment is a comment; the FROM/USER
// instructions around it are code. This is the language the IAC-121 keyword bug
// lived in — a HEALTHCHECK mentioned only in a comment must be classified as a
// comment so it cannot satisfy the absence rule.
func TestScanDockerfileComment(t *testing.T) {
	src := "FROM alpine:3.20\n" +
		"# no HEALTHCHECK is needed for a one-shot CLI\n" +
		"USER nobody\n"
	if k := kindOfSubstring(t, LangDockerfile, src, "no HEALTHCHECK is needed"); k != KindComment {
		t.Errorf("commented HEALTHCHECK mention must be a comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangDockerfile, src, "FROM alpine:3.20"); k != KindCode {
		t.Errorf("FROM instruction must be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangDockerfile, src, "USER nobody"); k != KindCode {
		t.Errorf("USER instruction must be code, got %v", k)
	}
}

// TestConfigHashNotCommentWithoutLeadingSpace: a `#` not preceded by whitespace
// (e.g. a URL fragment or an identifier `abc#x`) is NOT a comment — it is part
// of the value. Treating it as a comment would cut real content.
func TestConfigHashNotCommentWithoutLeadingSpace(t *testing.T) {
	src := "value: abc#attest\n"
	if k := kindOfSubstring(t, LangYAML, src, "abc#attest"); k != KindCode {
		t.Errorf("`abc#attest` (no leading space before #) must be code, got %v", k)
	}
}

// TestHashCommentStart is the single-line comment-boundary primitive that the
// core/rules absence matcher relies on. It must find a genuine trailing/whole
// line `#` comment, but NEVER report a `#` that sits inside a quoted value, a
// JSON string, or a URL fragment — cutting such a `#` would strip real content
// and flip a present property to absent (a false positive for a security tool).
func TestHashCommentStart(t *testing.T) {
	cases := []struct {
		name string
		line string
		want int
	}{
		{"whole-line comment", "# no HEALTHCHECK here", 0},
		{"trailing comment, no prior quote", "uses: actions/upload-artifact@sha # attested elsewhere", 34},
		{"hash inside double quotes is kept", `name: "release # attested"`, -1},
		{"hash inside single quotes is kept", "tag: 'v1 # attest'", -1},
		{"url fragment inside quotes is kept", `url: "https://x/a#attest"`, -1},
		{"hash not preceded by whitespace", "value: abc#attest", -1},
		{"comment after an unquoted value", "attestations: read # keep this key", 19},
		{"JSON: all # are inside quotes", `{"note": "requires # attestation"}`, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := HashCommentStart([]byte(tc.line)); got != tc.want {
				t.Errorf("HashCommentStart(%q) = %d, want %d", tc.line, got, tc.want)
			}
		})
	}
}

// TestConfigLangFromPathUnchanged documents a deliberate scoping decision:
// LangYAML / LangDockerfile are reachable via Classify (and the absence
// matcher's HashCommentStart) but are intentionally NOT wired into LangFromPath.
// Wiring them would silently change what the secrets, taint, ai, and agentflow
// analyzers do on every .yml/.yaml/Dockerfile (they all gate on LangFromPath),
// which is out of scope for the comment-context unification. This test pins that
// choice so a future edit to LangFromPath is a conscious one.
func TestConfigLangFromPathUnchanged(t *testing.T) {
	for _, p := range []string{"ci.yml", ".github/workflows/build.yaml", "Dockerfile"} {
		if got := LangFromPath(p); got != LangUnknown {
			t.Errorf("LangFromPath(%q) = %v, want LangUnknown (see scan_config.go)", p, got)
		}
	}
}
