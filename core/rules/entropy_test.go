package rules

import (
	"math"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// ShannonEntropy tests
// ---------------------------------------------------------------------------

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantMin float64
		wantMax float64
	}{
		{
			name:    "all same characters",
			input:   "aaaa",
			wantMin: 0.0,
			wantMax: 0.0,
		},
		{
			name:    "four distinct characters",
			input:   "abcd",
			wantMin: 2.0,
			wantMax: 2.0,
		},
		{
			name:    "two characters even split",
			input:   "aabb",
			wantMin: 1.0,
			wantMax: 1.0,
		},
		{
			name:    "empty string",
			input:   "",
			wantMin: 0.0,
			wantMax: 0.0,
		},
		{
			name:    "high entropy random-like string",
			input:   "aK3jR8mZ2pL5nW9xQ4vB7yD1sF6hT0c",
			wantMin: 4.0,
			wantMax: 6.0,
		},
		{
			name:    "base64 encoded string",
			input:   "dGhpcyBpcyBhIHNlY3JldCB0b2tlbg==",
			wantMin: 3.5,
			wantMax: 6.0,
		},
		{
			name:    "hex string",
			input:   "deadbeefcafebabe1234567890abcdef",
			wantMin: 3.5,
			wantMax: 5.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShannonEntropy(tt.input)
			if got < tt.wantMin-0.001 || got > tt.wantMax+0.001 {
				t.Fatalf("ShannonEntropy(%q) = %f, want [%f, %f]",
					tt.input, got, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestShannonEntropy_KnownValues(t *testing.T) {
	// "abcd" has exactly 4 equally probable chars => log2(4) = 2.0
	got := ShannonEntropy("abcd")
	if math.Abs(got-2.0) > 0.001 {
		t.Fatalf("expected entropy of 2.0 for 'abcd', got %f", got)
	}

	// "aaaa" => 0.0 (single character repeated)
	got = ShannonEntropy("aaaa")
	if math.Abs(got-0.0) > 0.001 {
		t.Fatalf("expected entropy of 0.0 for 'aaaa', got %f", got)
	}

	// "ab" => log2(2) = 1.0
	got = ShannonEntropy("ab")
	if math.Abs(got-1.0) > 0.001 {
		t.Fatalf("expected entropy of 1.0 for 'ab', got %f", got)
	}
}

// ---------------------------------------------------------------------------
// EntropyMatcher: quoted string detection
// ---------------------------------------------------------------------------

func TestEntropyMatcher_QuotedStrings(t *testing.T) {
	m := &EntropyMatcher{}

	// High-entropy double-quoted value on a line with secret context.
	content := []byte(`secret_key = "aK3jR8mZ2pL5nW9xQ4vB7yD1sF6hT0c"`)
	rule := Rule{MatcherType: "entropy"}

	results := m.Match(content, &rule)
	if len(results) == 0 {
		t.Fatal("expected at least 1 match for high-entropy quoted string with secret context")
	}

	found := false
	for _, r := range results {
		if r.MatchText == "aK3jR8mZ2pL5nW9xQ4vB7yD1sF6hT0c" {
			found = true
			if r.Line != 1 {
				t.Fatalf("expected line 1, got %d", r.Line)
			}
		}
	}
	if !found {
		t.Fatal("expected match text 'aK3jR8mZ2pL5nW9xQ4vB7yD1sF6hT0c'")
	}
}

func TestEntropyMatcher_SingleQuotedStrings(t *testing.T) {
	m := &EntropyMatcher{}

	content := []byte(`token = 'xK9mR2pL5nW7vB4yD1sF6hT0cQ3jZ8a'`)
	rule := Rule{MatcherType: "entropy"}

	results := m.Match(content, &rule)
	if len(results) == 0 {
		t.Fatal("expected at least 1 match for high-entropy single-quoted string")
	}

	found := false
	for _, r := range results {
		if r.MatchText == "xK9mR2pL5nW7vB4yD1sF6hT0cQ3jZ8a" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected match for single-quoted high-entropy string")
	}
}

// ---------------------------------------------------------------------------
// EntropyMatcher: assignment RHS detection
// ---------------------------------------------------------------------------

func TestEntropyMatcher_AssignmentRHS(t *testing.T) {
	m := &EntropyMatcher{}

	// Unquoted assignment value that looks like a secret token.
	content := []byte("SECRET_KEY = aK3jR8mZ2pL5nW9xQ4vB7yD1sF6hT0c\n")
	rule := Rule{MatcherType: "entropy"}

	results := m.Match(content, &rule)
	if len(results) == 0 {
		t.Fatal("expected at least 1 match for high-entropy assignment RHS")
	}

	found := false
	for _, r := range results {
		if strings.Contains(r.MatchText, "aK3jR8mZ2pL5nW9x") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected to find the assignment RHS token")
	}
}

func TestEntropyMatcher_ColonAssignment(t *testing.T) {
	m := &EntropyMatcher{}

	// YAML-style colon assignment.
	content := []byte("api_key: aK3jR8mZ2pL5nW9xQ4vB7yD1sF6hT0c\n")
	rule := Rule{MatcherType: "entropy"}

	results := m.Match(content, &rule)
	if len(results) == 0 {
		t.Fatal("expected at least 1 match for colon-assigned high-entropy value")
	}
}

// A struct-literal field in Go/Rust/Swift uses the same `name: value` shape as
// YAML, so the colon tokenizer picks up the field's expression as if it were a
// value. `domain.PrePush.ConfigKey` is a selector expression with no value at
// scan time — but it is 24 chars of mixed case with dots (so the camelCase
// guard, which rejects non-alphanumerics, does not catch it) and its entropy is
// 4.085, over SEC-163's context-boosted 4.0. It was reported as a "high-entropy
// hex string" despite containing no hex, and because such findings surface as
// code-scanning review comments it blocked a PR from merging.
func TestEntropyMatcher_SkipsMethodCallInStructLiteral(t *testing.T) {
	m := &EntropyMatcher{}
	rule := Rule{MatcherType: "entropy", Metadata: map[string]string{
		"entropy_threshold": "4.5", "require_context": "true",
	}}

	for _, line := range []string{
		"\t\tHook:          domain.PrePush.ConfigKey(),",
		"\t\tToken: config.Provider.SecretToken(),",
		"\t\tkey: obj.Nested.CredentialLookup(),",
	} {
		if results := m.Match([]byte(line+"\n"), &rule); len(results) != 0 {
			t.Errorf("flagged a method call as a secret in %q: %+v", strings.TrimSpace(line), results)
		}
	}
}

// The paren guard must not cost recall: a real secret is never followed by '('.
func TestEntropyMatcher_CallGuardKeepsRealSecrets(t *testing.T) {
	m := &EntropyMatcher{}
	rule := Rule{MatcherType: "entropy"}

	for _, line := range []string{
		"api_key: aK3jR8mZ2pL5nW9xQ4vB7yD1sF6hT0c",          // colon, unquoted
		"api_key = aK3jR8mZ2pL5nW9xQ4vB7yD1sF6hT0c",         // equals, unquoted
		"secret: aK3jR8mZ2pL5nW9xQ4vB7yD1sF6hT0c(notacall)", // paren later, not adjacent
	} {
		if results := m.Match([]byte(line+"\n"), &rule); len(results) == 0 {
			t.Errorf("lost a real secret in %q", line)
		}
	}
}

func TestEntropyMatcher_FatArrowAssignment(t *testing.T) {
	m := &EntropyMatcher{}

	// Ruby/JS-style fat arrow assignment.
	content := []byte("secret => aK3jR8mZ2pL5nW9xQ4vB7yD1sF6hT0c\n")
	rule := Rule{MatcherType: "entropy"}

	results := m.Match(content, &rule)
	if len(results) == 0 {
		t.Fatal("expected at least 1 match for fat-arrow assigned high-entropy value")
	}
}

// ---------------------------------------------------------------------------
// EntropyMatcher: base64 blob detection
// ---------------------------------------------------------------------------

func TestEntropyMatcher_Base64Blob(t *testing.T) {
	m := &EntropyMatcher{}

	// A base64-encoded high-entropy blob with secret context to trigger
	// the context boost (threshold lowered by 0.5, entropy ~4.81 > 4.5).
	content := []byte("secret_key = R2x5cE9mN3hLajJiWXQ5d1F6TnZIc0E=\n")
	rule := Rule{MatcherType: "entropy"}

	results := m.Match(content, &rule)
	if len(results) == 0 {
		t.Fatal("expected at least 1 match for base64 blob with secret context")
	}

	found := false
	for _, r := range results {
		if strings.Contains(r.MatchText, "R2x5cE9mN3hLajJi") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected to find the base64 blob in match results")
	}
}

// TestEntropyMatcher_SkipsSRIIntegrityHash verifies that a Subresource
// Integrity (SRI) hash — a public, base64-encoded content digest prefixed by
// its algorithm (sha256-/sha384-/sha512-) — does not fire the entropy rules.
// SRI hashes are integrity values embedded in HTML/JSX/struct tags, not
// credentials; flagging them is the same false-positive class as lockfile
// hashes and git SHAs (precision-suite clean_identifiers.go).
func TestEntropyMatcher_SkipsSRIIntegrityHash(t *testing.T) {
	m := &EntropyMatcher{}
	// The base64 body carries a '+' and '/', high entropy, and secret-context
	// keyword "integrity" on the line — exactly the shape that used to fire.
	content := []byte("\tIntegrity string // sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8w\n")
	rule := Rule{MatcherType: "entropy", Metadata: map[string]string{"entropy_threshold": "5.0"}}

	if results := m.Match(content, &rule); len(results) != 0 {
		t.Fatalf("expected no matches for SRI integrity hash, got %d: %+v", len(results), results)
	}
}

// TestIsSRIIntegrityHashLine covers the SRI-prefix recognition helper directly.
func TestIsSRIIntegrityHashLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		col  int // 1-based column of the candidate within line
		want bool
	}{
		{"sha384", "x = sha384-oqVuAfXRKap7fdgcCY5uykM6", 12, true},
		{"sha256", "integrity=\"sha256-AbCdEf0123456789+/xyz\"", 19, true},
		{"sha512", "  sha512-ZZZ0123456789abcdefGHIJ", 10, true},
		{"no-prefix", "key = oqVuAfXRKap7fdgcCY5uykM6", 7, false},
		{"unrelated-word", "mysha384-oqVuAfXRKap7fdgcCY5", 10, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSRIIntegrityHash(tt.line, tt.col); got != tt.want {
				t.Fatalf("isSRIIntegrityHash(%q, %d) = %v, want %v", tt.line, tt.col, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// EntropyMatcher: hex string detection
// ---------------------------------------------------------------------------

func TestEntropyMatcher_HexString(t *testing.T) {
	m := &EntropyMatcher{}

	// Hex strings using only [0-9a-f] have a theoretical max entropy of 4.0
	// (16 distinct characters). Using mixed case pushes entropy higher. The
	// metadata threshold lets us test hex extraction specifically.
	content := []byte("hash = 0123456789abcdef0123456789ABCDEF\n")
	rule := Rule{
		MatcherType: "entropy",
		Metadata:    map[string]string{"entropy_threshold": "3.5"},
	}

	results := m.Match(content, &rule)
	if len(results) == 0 {
		t.Fatal("expected at least 1 match for hex string")
	}

	found := false
	for _, r := range results {
		if strings.Contains(r.MatchText, "0123456789abcdef") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected to find the hex string in match results")
	}
}

// ---------------------------------------------------------------------------
// EntropyMatcher: context boost
// ---------------------------------------------------------------------------

func TestEntropyMatcher_ContextBoost(t *testing.T) {
	m := &EntropyMatcher{}

	// A string with entropy between 4.5 and 5.0 — would NOT match at
	// default threshold (5.0), but SHOULD match when "password" is in the
	// line (threshold drops to 4.5).
	//
	// We use a carefully crafted string with known entropy ~4.585.
	// It has enough digits (>20%) to not be classified as camelCase.
	candidate := "aB3cD5eF7gH9iJ1kL2mN4oP6"
	entropy := ShannonEntropy(candidate)

	if entropy >= defaultEntropyThreshold {
		t.Skipf("candidate entropy %f is already above threshold %f; adjust test data",
			entropy, defaultEntropyThreshold)
	}
	if entropy < defaultEntropyThreshold-contextBoostReduction {
		t.Skipf("candidate entropy %f is below boosted threshold %f; adjust test data",
			entropy, defaultEntropyThreshold-contextBoostReduction)
	}

	// Without context: should NOT match.
	contentNoContext := []byte(`config = "` + candidate + `"` + "\n")
	rule := Rule{MatcherType: "entropy"}

	results := m.Match(contentNoContext, &rule)
	if len(results) != 0 {
		t.Fatalf("expected 0 matches without secret context, got %d (entropy=%f)",
			len(results), entropy)
	}

	// With context ("password" on the line): should match.
	contentWithContext := []byte(`password = "` + candidate + `"` + "\n")
	results = m.Match(contentWithContext, &rule)
	if len(results) == 0 {
		t.Fatalf("expected match with secret context boost (entropy=%f, boosted threshold=%f)",
			entropy, defaultEntropyThreshold-contextBoostReduction)
	}
}

func TestEntropyMatcher_ContextBoostKeywords(t *testing.T) {
	// Verify all secret hint keywords trigger the boost.
	m := &EntropyMatcher{}

	// Candidate with entropy between 4.5 and 5.0.
	candidate := "aB3cD5eF7gH9iJ1kL2mN4oP6"
	entropy := ShannonEntropy(candidate)

	if entropy >= defaultEntropyThreshold || entropy < defaultEntropyThreshold-contextBoostReduction {
		t.Skipf("candidate entropy %f not in boost range; adjust test data", entropy)
	}

	for _, keyword := range secretHints {
		t.Run(keyword, func(t *testing.T) {
			content := []byte(keyword + ` = "` + candidate + `"` + "\n")
			rule := Rule{MatcherType: "entropy"}
			results := m.Match(content, &rule)
			if len(results) == 0 {
				t.Fatalf("expected match with keyword %q on line (entropy=%f)", keyword, entropy)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// EntropyMatcher: false positive resistance
// ---------------------------------------------------------------------------

func TestEntropyMatcher_NoFalsePositives(t *testing.T) {
	m := &EntropyMatcher{}
	rule := Rule{MatcherType: "entropy"}

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "URL should not trigger",
			content: `link = "https://example.com/api/v2/resources/items"`,
		},
		{
			name:    "short string should not trigger",
			content: `name = "abc"`,
		},
		{
			name:    "all lowercase word should not trigger",
			content: `description = "implementation"`,
		},
		{
			name:    "common Go import path",
			content: `import "github.com/user/repo/package"`,
		},
		{
			name:    "low entropy repeated chars",
			content: `padding = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"`,
		},
		{
			name:    "simple numeric value",
			content: `port = 8080`,
		},
		{
			name:    "plain English sentence",
			content: `message = "the quick brown fox jumps"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := m.Match([]byte(tt.content), &rule)
			if len(results) != 0 {
				t.Fatalf("expected 0 matches for %q, got %d (text=%q)",
					tt.name, len(results), results[0].MatchText)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// EntropyMatcher: threshold from metadata
// ---------------------------------------------------------------------------

func TestEntropyMatcher_ThresholdFromMetadata(t *testing.T) {
	m := &EntropyMatcher{}

	// Use a candidate string with known entropy ~4.585 (above 3.0, below 5.0).
	// Has enough digits to not be filtered as camelCase.
	candidate := "aB3cD5eF7gH9iJ1kL2mN4oP6"
	entropy := ShannonEntropy(candidate)

	content := []byte(`config = "` + candidate + `"` + "\n")

	t.Run("default threshold should not match", func(t *testing.T) {
		rule := Rule{MatcherType: "entropy"}
		results := m.Match(content, &rule)
		if entropy < defaultEntropyThreshold && len(results) != 0 {
			t.Fatalf("expected no match at default threshold %f for entropy %f",
				defaultEntropyThreshold, entropy)
		}
	})

	t.Run("lowered threshold should match", func(t *testing.T) {
		rule := Rule{
			MatcherType: "entropy",
			Metadata:    map[string]string{"entropy_threshold": "3.0"},
		}
		results := m.Match(content, &rule)
		if entropy >= 3.0 && len(results) == 0 {
			t.Fatalf("expected match at threshold 3.0 for entropy %f", entropy)
		}
	})

	t.Run("raised threshold should not match", func(t *testing.T) {
		rule := Rule{
			MatcherType: "entropy",
			Metadata:    map[string]string{"entropy_threshold": "6.0"},
		}
		results := m.Match(content, &rule)
		if len(results) != 0 {
			t.Fatalf("expected no match at threshold 6.0 for entropy %f", entropy)
		}
	})

	t.Run("invalid threshold falls back to default", func(t *testing.T) {
		rule := Rule{
			MatcherType: "entropy",
			Metadata:    map[string]string{"entropy_threshold": "not-a-number"},
		}
		results := m.Match(content, &rule)
		if entropy < defaultEntropyThreshold && len(results) != 0 {
			t.Fatal("invalid metadata should fall back to default threshold")
		}
	})
}

// ---------------------------------------------------------------------------
// EntropyMatcher: line and column positions
// ---------------------------------------------------------------------------

func TestEntropyMatcher_LineAndColumn(t *testing.T) {
	m := &EntropyMatcher{}

	content := []byte("line one\nsecret = \"aK3jR8mZ2pL5nW9xQ4vB7yD1sF6hT0c\"\nline three\n")
	rule := Rule{MatcherType: "entropy"}

	results := m.Match(content, &rule)
	if len(results) == 0 {
		t.Fatal("expected at least 1 match")
	}

	// The secret is on line 2.
	found := false
	for _, r := range results {
		if r.MatchText == "aK3jR8mZ2pL5nW9xQ4vB7yD1sF6hT0c" {
			found = true
			if r.Line != 2 {
				t.Fatalf("expected line 2, got %d", r.Line)
			}
			if r.Column < 1 {
				t.Fatalf("expected positive column, got %d", r.Column)
			}
		}
	}
	if !found {
		t.Fatal("expected to find the high-entropy string in results")
	}
}

// ---------------------------------------------------------------------------
// EntropyMatcher: multiline content
// ---------------------------------------------------------------------------

func TestEntropyMatcher_MultipleLines(t *testing.T) {
	m := &EntropyMatcher{}

	content := []byte(strings.Join([]string{
		`# Configuration file`,
		`db_host = "localhost"`,
		`db_password = "aK3jR8mZ2pL5nW9xQ4vB7yD1sF6hT0c"`,
		`db_port = 5432`,
		`api_token = "xQ9mR2pL5nW7vB4yD1sF6hT0cK3jZ8a"`,
		``,
	}, "\n"))
	rule := Rule{MatcherType: "entropy"}

	results := m.Match(content, &rule)

	// Should find at least 2 high-entropy secrets.
	if len(results) < 2 {
		t.Fatalf("expected at least 2 matches in multiline content, got %d", len(results))
	}

	// Verify line numbers.
	lineSet := make(map[int]bool)
	for _, r := range results {
		lineSet[r.Line] = true
	}
	if !lineSet[3] {
		t.Fatal("expected a match on line 3 (db_password)")
	}
	if !lineSet[5] {
		t.Fatal("expected a match on line 5 (api_token)")
	}
}

// ---------------------------------------------------------------------------
// EntropyMatcher: short strings are ignored
// ---------------------------------------------------------------------------

func TestEntropyMatcher_ShortStringsIgnored(t *testing.T) {
	m := &EntropyMatcher{}

	// Short but high-entropy string — should NOT be flagged.
	content := []byte(`key = "aB3$"` + "\n")
	rule := Rule{MatcherType: "entropy"}

	results := m.Match(content, &rule)
	if len(results) != 0 {
		t.Fatalf("expected 0 matches for short string, got %d", len(results))
	}
}

// ---------------------------------------------------------------------------
// EntropyMatcher: registry integration
// ---------------------------------------------------------------------------

func TestDefaultMatcherRegistry_IncludesEntropy(t *testing.T) {
	reg := NewDefaultMatcherRegistry()
	if reg.Get("entropy") == nil {
		t.Fatal("expected entropy matcher to be registered in default registry")
	}
}

// ---------------------------------------------------------------------------
// isLikelyNotSecret tests
// ---------------------------------------------------------------------------

func TestIsLikelyNotSecret(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{"http URL", "http://example.com/api/v2", true},
		{"https URL", "https://example.com/api/v2", true},
		{"all lowercase letters", "implementation", true},
		{"mixed case token", "aK3jR8mZ2pL5nW9x", false},
		{"hex with digits", "deadbeef12345678", false},
		{"base64 with special chars", "R2x5cE9m+N3hLaj/JiWX=", false},
		// New false-positive filters:
		{"git SHA (40 hex)", "abc123def456abc123def456abc123def456abc1", true},
		{"SHA-256 checksum (64 hex)", "abc123def456abc123def456abc123def456abc123def456abc123def456abc1", true},
		{"file path with slash", "src/components/Button.tsx", true},
		{"Go import path", "github.com/user/repo/pkg", true},
		{"Windows file path", "src\\components\\Button.tsx", true},
		{"version string", "v1.2.3-beta.1", true},
		{"version no prefix", "1.0.0", true},
		{"camelCase identifier", "calculateTotalAmount", true},
		{"PascalCase identifier", "CalculateTotalAmount", true},
		{"mostly digits", "12345678901234567890", true},
		{"all uppercase", "PRODUCTION", true},
		// SCREAMING_SNAKE_CASE constant names — never credentials.
		{"screaming snake case", "DEFAULT_RUN_CONTEXT_THREAD_ID_KEY", true},
		{"screaming snake with digits", "MAX_RETRY_COUNT_3", true},
		// snake_case attribute access chains — never credentials.
		{"snake case attr chain", "resolved_options.run_context_thread_id_key", true},
		{"simple snake case var", "run_context_thread_id", true},
		// Template expressions (f-strings, shell substitution) — never raw credentials.
		{"fstring template braces", "{DEFAULT_RUN_CONTEXT_THREAD_ID_KEY}_{suffix}", true},
		{"shell var substitution", "${MY_SECRET_TOKEN}_value", true},
		// Real secret tokens must still be detected.
		{"random token no underscore", "aK3jR8mZ2pL5nW9xQ7vB", false},
		{"hex-like mixed", "a1B2c3D4e5F6g7H8i9J0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isLikelyNotSecret(tt.s)
			if got != tt.want {
				t.Fatalf("isLikelyNotSecret(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// hasSecretContext tests
// ---------------------------------------------------------------------------

func TestHasSecretContext(t *testing.T) {
	tests := []struct {
		name string
		line string
		want bool
	}{
		{"contains password", "db_password = value", true},
		{"contains secret", "my_secret = value", true},
		{"contains key", "api_key = value", true},
		{"contains token", "auth_token = value", true},
		{"contains credential", "user_credential = value", true},
		{"contains private", "private_key = value", true},
		{"no hint", "db_host = localhost", false},
		{"empty line", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasSecretContext(tt.line)
			if got != tt.want {
				t.Fatalf("hasSecretContext(%q) = %v, want %v", tt.line, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// EntropyMatcher: empty and nil content
// ---------------------------------------------------------------------------

func TestEntropyMatcher_EmptyContent(t *testing.T) {
	m := &EntropyMatcher{}
	rule := Rule{MatcherType: "entropy"}

	results := m.Match([]byte{}, &rule)
	if len(results) != 0 {
		t.Fatalf("expected 0 matches for empty content, got %d", len(results))
	}

	results = m.Match(nil, &rule)
	if len(results) != 0 {
		t.Fatalf("expected 0 matches for nil content, got %d", len(results))
	}
}

// ---------------------------------------------------------------------------
// EntropyMatcher: require_context
// ---------------------------------------------------------------------------

func TestEntropyMatcher_RequireContext_SkipsWithoutHint(t *testing.T) {
	m := &EntropyMatcher{}

	// High-entropy string on a line WITHOUT any secret hint keyword.
	// With require_context=true, this should NOT fire.
	content := []byte(`config = "aK3jR8mZ2pL5nW9xQ4vB7yD1sF6hT0c"` + "\n")
	rule := Rule{
		MatcherType: "entropy",
		Metadata:    map[string]string{"entropy_threshold": "4.0", "require_context": "true"},
	}

	results := m.Match(content, &rule)
	if len(results) != 0 {
		t.Fatalf("expected 0 matches with require_context=true and no hint, got %d", len(results))
	}
}

func TestEntropyMatcher_RequireContext_MatchesWithHint(t *testing.T) {
	m := &EntropyMatcher{}

	// High-entropy string on a line WITH a secret hint keyword.
	content := []byte(`password = "aK3jR8mZ2pL5nW9xQ4vB7yD1sF6hT0c"` + "\n")
	rule := Rule{
		MatcherType: "entropy",
		Metadata:    map[string]string{"entropy_threshold": "4.0", "require_context": "true"},
	}

	results := m.Match(content, &rule)
	if len(results) == 0 {
		t.Fatal("expected match with require_context=true when hint keyword is present")
	}
}

func TestEntropyMatcher_RequireContext_DefaultFalse(t *testing.T) {
	m := &EntropyMatcher{}

	// Without require_context metadata, the rule should match without hints.
	content := []byte(`config = "aK3jR8mZ2pL5nW9xQ4vB7yD1sF6hT0c"` + "\n")
	rule := Rule{
		MatcherType: "entropy",
		Metadata:    map[string]string{"entropy_threshold": "4.0"},
	}

	results := m.Match(content, &rule)
	if len(results) == 0 {
		t.Fatal("expected match without require_context (defaults to false)")
	}
}

// ---------------------------------------------------------------------------
// isLikelyNotSecret: new helper function tests
// ---------------------------------------------------------------------------

func TestIsAllHex(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{"hex lowercase", "deadbeef", true},
		{"hex uppercase", "DEADBEEF", true},
		{"hex mixed", "DeAdBeEf01234567", true},
		{"not hex", "ghijklmn", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isAllHex(tt.s); got != tt.want {
				t.Fatalf("isAllHex(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestIsVersionString(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"v1.2.3", true},
		{"1.0.0", true},
		{"v1.2.3-beta.1", true},
		{"V2.0.0", true},
		{"abc", false},
		{"v", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := isVersionString(tt.s); got != tt.want {
				t.Fatalf("isVersionString(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestIsCamelOrPascalCase(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"calculateTotal", true},
		{"CalculateTotal", true},
		{"myVariableName", true},
		{"ALLCAPS", false},
		{"alllower", false},
		{"ab", false},
		{"a1B2c3D4", false}, // too many digits (>20%)
		{"has-dashes", false},
		{"aK3jR8mZ2pL5nW9x", false}, // random token with many digits
	}
	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := isCamelOrPascalCase(tt.s); got != tt.want {
				t.Fatalf("isCamelOrPascalCase(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestIsMostlyDigits(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"12345678901234567890", true},
		{"12345ab", true},  // 5/7 = 71.4% > 70%
		{"1234abc", false}, // 4/7 = 57% < 70%
		{"abcdefgh", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := isMostlyDigits(tt.s); got != tt.want {
				t.Fatalf("isMostlyDigits(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestIsScreamingSnakeCase(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"DEFAULT_RUN_CONTEXT_THREAD_ID_KEY", true},
		{"MAX_RETRY_COUNT", true},
		{"MAX_RETRY_COUNT_3", true},
		{"PRODUCTION", false}, // no underscore
		{"my_const", false},   // lowercase
		{"MixedCase", false},  // has lowercase
		{"A_B", false},        // too short (< 4 chars)
		{"AB_CD", true},
		{"", false},
		{"AB", false}, // too short, no underscore
	}
	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := isScreamingSnakeCase(tt.s); got != tt.want {
				t.Fatalf("isScreamingSnakeCase(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestIsLowercaseDotChain(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"resolved_options.run_context_thread_id_key", true},
		{"run_context_thread_id", true},
		{"some.module.method_name", true},
		{"MixedCase_something", false}, // has uppercase
		{"no_dot_and_under", true},     // underscore present, no dot — still matches
		{"plainword", false},           // no underscore
		{"SCREAMING_SNAKE", false},     // uppercase
		{"has+special", false},         // has +
		{"", false},
		{"a_b", false}, // too short (< 4 chars; never a candidate anyway)
		{"some_var", true},
	}
	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := isLowercaseDotChain(tt.s); got != tt.want {
				t.Fatalf("isLowercaseDotChain(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestContainsTemplateBraces(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"{DEFAULT_RUN_CONTEXT_THREAD_ID_KEY}_{suffix}", true},
		{"${MY_SECRET_TOKEN}", true},
		{"no braces here", false},
		{"{only open", false},
		{"only close}", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := containsTemplateBraces(tt.s); got != tt.want {
				t.Fatalf("containsTemplateBraces(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// EntropyMatcher: false positive regression tests for common patterns
// ---------------------------------------------------------------------------

func TestEntropyMatcher_FalsePositiveRegression(t *testing.T) {
	m := &EntropyMatcher{}
	rule := Rule{MatcherType: "entropy"}

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "git SHA in action pinning",
			content: `uses: actions/checkout@abc123def456abc123def456abc123def456abc1`,
		},
		{
			name:    "Go import path",
			content: `import "github.com/nox-hq/nox/core/rules"`,
		},
		{
			name:    "camelCase Go function name in string",
			content: `name = "calculateTotalAmountForUser"`,
		},
		{
			name:    "file path reference",
			content: `path = "src/components/UserProfile/index.tsx"`,
		},
		{
			name:    "version string",
			content: `version = "v1.2.3-beta.1+build.456"`,
		},
		{
			name:    "SHA-256 checksum",
			content: `sha256: abc123def456abc123def456abc123def456abc123def456abc123def456abc1`,
		},
		// Regression: openai-agents-python SEC-163 false positives (scan-of-week 2026-08-01)
		{
			name:    "SCREAMING_SNAKE constant in fstring template",
			content: `        return f"{DEFAULT_RUN_CONTEXT_THREAD_ID_KEY}_{suffix}"`,
		},
		{
			name:    "snake_case attribute access as kwarg value",
			content: `        configured_key=resolved_options.run_context_thread_id_key,`,
		},
		{
			name:    "PascalCase method call as assignment RHS",
			content: `        approval_key = RunContextWrapper._resolve_approval_key(interruption)`,
		},
		{
			name:    "PascalCase.from_state call as assignment RHS",
			content: `        inner = BlaxelSandboxSession.from_state(state, sandbox=blaxel_sandbox, token=self._token)`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := m.Match([]byte(tt.content), &rule)
			if len(results) != 0 {
				t.Fatalf("expected 0 matches for %q, got %d (text=%q)",
					tt.name, len(results), results[0].MatchText)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Edge-case coverage: short candidates, empty camelCase input, short upper
// ---------------------------------------------------------------------------

func TestEntropyMatcher_ShortCandidateSkipped(t *testing.T) {
	t.Parallel()

	// A candidate shorter than minCandidateLen (8) should be skipped
	// even if it has high entropy.
	m := &EntropyMatcher{}
	rule := Rule{
		ID:          "TEST-ENT-SHORT",
		MatcherType: "entropy",
		Severity:    "high",
	}
	// "aB3xZ!" is only 6 chars — below minCandidateLen.
	content := `SECRET=aB3xZ!`
	results := m.Match([]byte(content), &rule)
	if len(results) != 0 {
		t.Errorf("expected 0 matches for short candidate, got %d", len(results))
	}
}

func Test_isCamelOrPascalCase_EmptyString(t *testing.T) {
	t.Parallel()

	// When total (letters+digits) is 0, the function should return false.
	got := isCamelOrPascalCase("")
	if got {
		t.Error("expected false for empty string")
	}
}

func Test_isCamelOrPascalCase_PunctuationOnly(t *testing.T) {
	t.Parallel()

	// Only punctuation — letters=0, digits=0 → total=0 → should return false.
	got := isCamelOrPascalCase("---!!!")
	if got {
		t.Error("expected false for punctuation-only string")
	}
}

func Test_isAllUpperAlpha_ShortStrings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"empty", "", false},
		{"one char", "A", false},
		{"two chars", "AB", false},
		{"three chars", "ABC", false},
		{"four chars upper", "ABCD", true},
		{"four chars mixed", "ABcD", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAllUpperAlpha(tt.input)
			if got != tt.want {
				t.Errorf("isAllUpperAlpha(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Assignment tokenization edge cases
// ---------------------------------------------------------------------------

type assignmentCandidate struct {
	col  int
	text string
}

func collectAssignmentCandidates(line string) []assignmentCandidate {
	var out []assignmentCandidate
	extractAssignmentRHS(line, func(col int, text string) {
		out = append(out, assignmentCandidate{col: col, text: text})
	})
	return out
}

func TestExtractAssignmentRHS_SkipsComparisonsAndQuotes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		line string
	}{
		{
			name: "double equals",
			line: "value == other",
		},
		{
			name: "not equals",
			line: "value != other",
		},
		{
			name: "greater equals",
			line: "value >= other",
		},
		{
			name: "less equals",
			line: "value <= other",
		},
		{
			name: "double colon",
			line: "namespace::value",
		},
		{
			name: "quoted rhs",
			line: "token = \"quoted-value-should-skip\"",
		},
		{
			name: "short token",
			line: "token = short",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := collectAssignmentCandidates(tt.line)
			if len(got) != 0 {
				t.Fatalf("expected no candidates for %q, got %v", tt.line, got)
			}
		})
	}
}

func TestExtractAssignmentRHS_ExtractsValidTokens(t *testing.T) {
	t.Parallel()

	line := "api_key = aB3cD5eF7gH9iJ1kL2mN4oP6"
	got := collectAssignmentCandidates(line)
	if len(got) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(got))
	}
	if got[0].text != "aB3cD5eF7gH9iJ1kL2mN4oP6" {
		t.Fatalf("unexpected token: %q", got[0].text)
	}
	if got[0].col <= 1 {
		t.Fatalf("expected positive column, got %d", got[0].col)
	}

	line = "secret=>aK3jR8mZ2pL5nW9xQ4vB7yD1sF6hT0c"
	got = collectAssignmentCandidates(line)
	if len(got) != 1 {
		t.Fatalf("expected 1 candidate for fat arrow, got %d", len(got))
	}
	if got[0].text != "aK3jR8mZ2pL5nW9xQ4vB7yD1sF6hT0c" {
		t.Fatalf("unexpected fat-arrow token: %q", got[0].text)
	}

	line = "token: aK3jR8mZ2pL5nW9xQ4vB7yD1sF6hT0c"
	got = collectAssignmentCandidates(line)
	if len(got) != 1 {
		t.Fatalf("expected 1 candidate for colon assignment, got %d", len(got))
	}
}

func TestIsTokenChar(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ch   byte
		want bool
	}{
		{"lowercase", 'a', true},
		{"uppercase", 'Z', true},
		{"digit", '7', true},
		{"plus", '+', true},
		{"slash", '/', true},
		{"equals", '=', true},
		{"dash", '-', true},
		{"underscore", '_', true},
		{"dot", '.', true},
		{"at", '@', false},
		{"space", ' ', false},
		{"colon", ':', false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTokenChar(tt.ch); got != tt.want {
				t.Fatalf("isTokenChar(%q) = %v, want %v", tt.ch, got, tt.want)
			}
		})
	}
}

// Regression for #104: the generic entropy detectors must not flag
// natural-language prose, SQL, or format-string literals — they have high
// aggregate entropy but internal whitespace, and are not credentials. A
// compact secret token (no whitespace) must still be detected.
func TestEntropyMatcher_IgnoresProse(t *testing.T) {
	m := &EntropyMatcher{}
	rule := Rule{MatcherType: "entropy"}

	prose := []string{
		`msg := "Risk: the finding shows the 72-hour deadline may be missed (GDPR-Art-33)."`,
		`return "the key contractual provisions obligation (DORA-Art-30)."`,
		`pool.Exec(ctx, "ALTER ROLE lexora_app LOGIN PASSWORD 'app_pw'")`,
		`tmpl := "judgement was not the required JSON object {judgements: [{citation, bucket}]}"`,
	}
	for _, line := range prose {
		if got := m.Match([]byte(line), &rule); len(got) != 0 {
			t.Errorf("prose flagged as secret: %q -> %+v", line, got)
		}
	}

	// A real compact secret (no whitespace) is still caught.
	secret := []byte(`api_key = "aK3jR8mZ2pL5nW9xQ4vB7yD1sF6hT0c"`)
	if got := m.Match(secret, &rule); len(got) == 0 {
		t.Error("a real whitespace-free high-entropy secret must still be detected")
	}
}
