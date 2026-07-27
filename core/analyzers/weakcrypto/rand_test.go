package weakcrypto

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
)

// scanGo runs the analyzer over one Go source file and returns only the
// CRYPTO-002 findings, so a fixture that also trips CRYPTO-001 does not
// silently satisfy an assertion here.
func scanGo(t *testing.T, name, src string) []findings.Finding {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, filepath.Base(name))
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	fs, err := (&Analyzer{}).ScanArtifacts(context.Background(),
		[]discovery.Artifact{{Path: name, AbsPath: p}})
	if err != nil {
		t.Fatal(err)
	}
	var out []findings.Finding
	for _, f := range fs.Findings() {
		if f.RuleID == randRuleID {
			out = append(out, f)
		}
	}
	return out
}

// TestFlagsSecurityUseOfMathRand covers what the rule is FOR: a predictable
// draw that the surrounding names identify as security-bearing. Each case also
// asserts the context identifier the finding blames, so a case that starts
// passing for the wrong reason (a different name matching, or the enclosing
// function standing in for the variable) fails here.
func TestFlagsSecurityUseOfMathRand(t *testing.T) {
	for _, c := range []struct{ name, src, wantCtx string }{
		{
			name:    "assignment to a security-named variable",
			src:     "package m\nimport \"math/rand\"\nfunc f() { token := rand.Int63(); _ = token }",
			wantCtx: "token",
		},
		{
			name:    "math/rand/v2 is the same predictable generator",
			src:     "package m\nimport \"math/rand/v2\"\nfunc f() { sessionKey := rand.N(100); _ = sessionKey }",
			wantCtx: "sessionKey",
		},
		{
			name:    "aliased import",
			src:     "package m\nimport mrand \"math/rand\"\nfunc f() { apiKey := mrand.Intn(999999); _ = apiKey }",
			wantCtx: "apiKey",
		},
		{
			name:    "Read takes its meaning from the buffer it fills",
			src:     "package m\nimport \"math/rand\"\nfunc f() { nonce := make([]byte, 12); rand.Read(nonce) }",
			wantCtx: "nonce",
		},
		{
			name:    "struct field assignment",
			src:     "package m\nimport \"math/rand\"\nfunc f(u *User) { u.PasswordResetToken = fmt.Sprintf(\"%d\", rand.Int63()) }",
			wantCtx: "PasswordResetToken",
		},
		{
			name:    "composite literal field",
			src:     "package m\nimport \"math/rand\"\nfunc f() { s := Session{Token: rand.Int63()}; _ = s }",
			wantCtx: "Token",
		},
		{
			name:    "value handed to a setter",
			src:     "package m\nimport \"math/rand\"\nfunc f(c *C) { c.SetSessionID(rand.Int63()) }",
			wantCtx: "SetSessionID",
		},
		{
			name:    "seeded *rand.Rand receiver",
			src:     "package m\nimport \"math/rand\"\nfunc f() { r := rand.New(rand.NewSource(1)); csrf := r.Intn(1 << 31); _ = csrf }",
			wantCtx: "csrf",
		},
		{
			name:    "generator held in a struct field",
			src:     "package m\nimport \"math/rand\"\ntype S struct{ rng *rand.Rand }\nfunc (s *S) f() { s.rng = rand.New(rand.NewSource(1)); otp := s.rng.Intn(1000000); _ = otp }",
			wantCtx: "otp",
		},
		{
			// The classic weak password generator: no variable says "password",
			// only the function does — and it says it while claiming to produce.
			name:    "producer function name, neutral variables",
			src:     "package m\nimport \"math/rand\"\nconst charset = \"abc\"\nfunc newPassword(n int) string {\n\tb := make([]byte, n)\n\tfor i := range b {\n\t\tb[i] = charset[rand.Intn(len(charset))]\n\t}\n\treturn string(b)\n}",
			wantCtx: "newPassword",
		},
		{
			name:    "producer function with no assignment at all",
			src:     "package m\nimport \"math/rand\"\nfunc generateToken() string { b := make([]byte, 16); rand.Read(b); return string(b) }",
			wantCtx: "generateToken",
		},
		{
			name:    "salt from a float draw",
			src:     "package m\nimport \"math/rand\"\nfunc f() { salt := rand.Float64(); _ = salt }",
			wantCtx: "salt",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := scanGo(t, "a.go", c.src)
			if len(got) != 1 {
				t.Fatalf("got %d findings, want 1: %s", len(got), c.src)
			}
			if got[0].Metadata["context"] != c.wantCtx {
				t.Errorf("blamed context %q, want %q", got[0].Metadata["context"], c.wantCtx)
			}
			if got[0].Severity != findings.SeverityHigh {
				t.Errorf("severity %q, want high", got[0].Severity)
			}
		})
	}
}

// TestIgnoresBenignRandomness is the half of this rule that matters most.
// `math/rand` is CORRECT for every case below; flagging them is what would get
// CRYPTO-002 suppressed org-wide, which costs more than the rule is worth.
func TestIgnoresBenignRandomness(t *testing.T) {
	for _, c := range []struct{ name, src string }{
		{
			name: "retry jitter",
			src:  "package m\nimport \"math/rand\"\nfunc f() { jitter := rand.Intn(1000); _ = jitter }",
		},
		{
			name: "exponential backoff spread",
			src:  "package m\nimport \"math/rand\"\nfunc backoff(attempt int) time.Duration {\n\tbase := time.Second * time.Duration(1<<attempt)\n\treturn base + time.Duration(rand.Int63n(int64(base/2)))\n}",
		},
		{
			// A benign word vetoes even though "auth" sits in the function name.
			name: "jittered sleep inside an auth path",
			src:  "package m\nimport \"math/rand\"\nfunc (c *Client) authRetry() { time.Sleep(time.Duration(rand.Intn(500)) * time.Millisecond) }",
		},
		{
			name: "load-balancer selection",
			src:  "package m\nimport \"math/rand\"\nfunc f(backends []string) { n := rand.Intn(len(backends)); _ = backends[n] }",
		},
		{
			name: "shuffling",
			src:  "package m\nimport \"math/rand\"\nfunc f(keys []string) { rand.Shuffle(len(keys), func(i, j int) { keys[i], keys[j] = keys[j], keys[i] }) }",
		},
		{
			name: "sampling helper whose name mentions tokens",
			src:  "package m\nimport \"math/rand\"\nfunc sampleTokens(n int) int { return rand.Intn(n) }",
		},
		{
			// A random draw somewhere inside an auth handler is not evidence
			// that the value is a secret; only a producer verb makes the
			// function name accuse.
			name: "neutral draw inside a security-named handler",
			src:  "package m\nimport \"math/rand\"\nfunc handleAuth() { n := rand.Intn(10); _ = n }",
		},
		{
			name: "seeding a generator",
			src:  "package m\nimport \"math/rand\"\nfunc f() { seed := rand.Int63(); _ = rand.New(rand.NewSource(seed)) }",
		},
		{
			// Word-level matching, not substring: neither of these is a key.
			name: "identifiers that merely contain security substrings",
			src:  "package m\nimport \"math/rand\"\nfunc f() { monkey := rand.Intn(10); keyboard := rand.Intn(10); _, _ = monkey, keyboard }",
		},
		{
			name: "quantity named for a secret is not the secret",
			src:  "package m\nimport \"math/rand\"\nfunc f() { maxTokens := rand.Intn(4096); _ = maxTokens }",
		},
		{
			name: "len-bounded draw is a choice however it is named",
			src:  "package m\nimport \"math/rand\"\nfunc f(c *C) { keyInd := rand.Intn(len(c.objects)); _ = keyInd }",
		},
		{
			name: "lookup by a random entry",
			src:  "package m\nimport \"math/rand\"\nfunc f(c *C) { _ = c.GetByKey(strconv.Itoa(rand.Int())) }",
		},
		{
			name: "a benign string literal in the same call exonerates",
			src:  "package m\nimport \"math/rand\"\nfunc f() { key := fmt.Sprintf(\"cache_key_%d\", rand.Intn(50)); _ = key }",
		},
		{
			name: "commented-out code and string literals are not code",
			src:  "package m\nimport \"math/rand\"\n// token := rand.Int63() -- removed\nfunc f() { x := \"token = rand.Int63()\"; _ = x; _ = rand.Intn(2) }",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := scanGo(t, "a.go", c.src); len(got) != 0 {
				t.Errorf("got %d findings, want 0 — math/rand is correct here: %s\n%s",
					len(got), got[0].Message, c.src)
			}
		})
	}
}

// TestNeverFlagsCryptoRand guards the one false positive that would discredit
// the rule outright: `crypto/rand` is the API this rule TELLS people to use,
// and it is spelled `rand.Read` too. Only resolving the import path keeps them
// apart — a text pattern cannot.
func TestNeverFlagsCryptoRand(t *testing.T) {
	for _, c := range []struct{ name, src string }{
		{
			name: "crypto/rand filling a token",
			src:  "package m\nimport \"crypto/rand\"\nfunc f() { token := make([]byte, 32); rand.Read(token); _ = token }",
		},
		{
			name: "crypto/rand inside a key generator",
			src:  "package m\nimport \"crypto/rand\"\nfunc generateSessionKey() []byte { key := make([]byte, 32); rand.Read(key); return key }",
		},
		{
			// Both packages in one file: the crypto one does the security work,
			// the math one does jitter. Neither may be reported.
			name: "both packages imported, each used correctly",
			src:  "package m\nimport (\n\t\"crypto/rand\"\n\tmrand \"math/rand\"\n)\nfunc f() { token := make([]byte, 32); rand.Read(token); jitter := mrand.Intn(9); _, _ = token, jitter }",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := scanGo(t, "a.go", c.src); len(got) != 0 {
				t.Errorf("got %d findings, want 0 — crypto/rand is the CORRECT API: %s", len(got), c.src)
			}
		})
	}
}

// TestAliasedCryptoRandStillFlagsMathRand is the mirror image: when the aliases
// are swapped, the math/rand call must still be found. Together with the test
// above this proves the decision is made on the import PATH, not on the
// identifier `rand`.
func TestAliasedCryptoRandStillFlagsMathRand(t *testing.T) {
	src := "package m\nimport (\n\tcrand \"crypto/rand\"\n\t\"math/rand\"\n)\nfunc f() { token := rand.Int63(); k := make([]byte, 8); crand.Read(k); _, _ = token, k }"
	got := scanGo(t, "a.go", src)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Metadata["context"] != "token" {
		t.Errorf("blamed %q, want token", got[0].Metadata["context"])
	}
}

// TestDocumentedFalseNegatives pins the limits of a naming heuristic. These
// ARE insecure, and the rule does not catch them. They are asserted so the
// boundary is explicit rather than folklore: if a later change starts catching
// one, this test fails and the remediation text should be updated to match.
func TestDocumentedFalseNegatives(t *testing.T) {
	for _, c := range []struct{ name, src string }{
		{
			// Nothing in scope is named for what the bytes are.
			name: "no descriptive names anywhere",
			src:  "package m\nimport \"math/rand\"\nfunc f() { b := make([]byte, 16); rand.Read(b); _ = b }",
		},
		{
			// Needs value tracking across statements, which is go/types work.
			name: "value reaches the security name in a later statement",
			src:  "package m\nimport \"math/rand\"\nfunc f() { a, b := rand.Intn(1), rand.Intn(2); token := a + b; _ = token }",
		},
		{
			// A dot import makes the call indistinguishable from a local
			// function without type information.
			name: "dot import",
			src:  "package m\nimport . \"math/rand\"\nfunc f() { token := Int63(); _ = token }",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := scanGo(t, "a.go", c.src); len(got) != 0 {
				t.Errorf("got %d findings, want 0 — this is a DOCUMENTED false negative; "+
					"if it is now caught, update the remediation text and this test", len(got))
			}
		})
	}
}

// TestSkipsTestFiles — fixtures use predictable randomness deliberately, and
// determinism in a test is a feature.
func TestRandSkipsTestFiles(t *testing.T) {
	src := "package m\nimport \"math/rand\"\nfunc f() { token := rand.Int63(); _ = token }"
	if got := scanGo(t, "a_test.go", src); len(got) != 0 {
		t.Errorf("got %d findings in a test file, want 0", len(got))
	}
}

// TestOneFindingPerLine — several draws on one line are one problem.
func TestOneFindingPerLine(t *testing.T) {
	src := "package m\nimport \"math/rand\"\nfunc f() { token, secret := rand.Int63(), rand.Int63(); _, _ = token, secret }"
	if got := scanGo(t, "a.go", src); len(got) != 1 {
		t.Fatalf("got %d findings, want 1 per line", len(got))
	}
}

// TestNonCompilingFileDegrades — a partial parse must not panic or crash the
// scan, matching the Go taint extractor's behaviour.
func TestNonCompilingFileDegrades(t *testing.T) {
	src := "package m\nimport \"math/rand\"\nfunc f() { token := rand.Int63(); _ = token\n// missing brace"
	if got := scanGo(t, "a.go", src); len(got) != 1 {
		t.Fatalf("got %d findings from a partial parse, want 1", len(got))
	}
}

func TestIdentWords(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
	}{
		{"sessionToken", []string{"session", "token"}},
		{"session_token", []string{"session", "token"}},
		{"APIKey", []string{"api", "key"}},
		{"IV", []string{"iv"}},
		{"csrfToken2", []string{"csrf", "token"}},
		{"monkey", []string{"monkey"}},
		{"keyboard", []string{"keyboard"}},
	} {
		got := identWords(c.in)
		if len(got) != len(c.want) {
			t.Errorf("identWords(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("identWords(%q) = %v, want %v", c.in, got, c.want)
				break
			}
		}
	}
}

func TestRandRuleRegistered(t *testing.T) {
	r, ok := (&Analyzer{}).Rules().ByID(randRuleID)
	if !ok {
		t.Fatalf("%s not in the rule catalogue", randRuleID)
	}
	if r.Severity != findings.SeverityHigh {
		t.Errorf("severity %q, want high — a medium rule does not gate in a "+
			"net-new-critical/high CI policy, which makes the rule decorative", r.Severity)
	}
	if r.Confidence != findings.ConfidenceMedium {
		t.Errorf("confidence %q, want medium", r.Confidence)
	}
	if r.Metadata["cwe"] != "CWE-338" {
		t.Errorf("cwe = %q, want CWE-338", r.Metadata["cwe"])
	}
	// The remediation must name crypto/rand and must admit the false negatives;
	// a naming heuristic that presents itself as exhaustive is worse than one
	// that says what it misses.
	if !strings.Contains(r.Remediation, "crypto/rand") {
		t.Error("remediation does not name the replacement API")
	}
	if !strings.Contains(r.Remediation, "will NOT be caught") {
		t.Error("remediation does not state that the rule misses neutrally-named generators")
	}
}
