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

	// High-entropy double-quoted value on a single line.
	content := []byte(`config_val = "aK3jR8mZ2pL5nW9xQ4vB7yD1sF6hT0c"`)
	rule := Rule{MatcherType: "entropy"}

	results := m.Match(content, rule)
	if len(results) == 0 {
		t.Fatal("expected at least 1 match for high-entropy quoted string")
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

	results := m.Match(content, rule)
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

	results := m.Match(content, rule)
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

	results := m.Match(content, rule)
	if len(results) == 0 {
		t.Fatal("expected at least 1 match for colon-assigned high-entropy value")
	}
}

func TestEntropyMatcher_FatArrowAssignment(t *testing.T) {
	m := &EntropyMatcher{}

	// Ruby/JS-style fat arrow assignment.
	content := []byte("secret => aK3jR8mZ2pL5nW9xQ4vB7yD1sF6hT0c\n")
	rule := Rule{MatcherType: "entropy"}

	results := m.Match(content, rule)
	if len(results) == 0 {
		t.Fatal("expected at least 1 match for fat-arrow assigned high-entropy value")
	}
}

// ---------------------------------------------------------------------------
// EntropyMatcher: base64 blob detection
// ---------------------------------------------------------------------------

func TestEntropyMatcher_Base64Blob(t *testing.T) {
	m := &EntropyMatcher{}

	// A base64-encoded high-entropy blob (entropy ~4.81).
	content := []byte("data = R2x5cE9mN3hLajJiWXQ5d1F6TnZIc0E=\n")
	rule := Rule{MatcherType: "entropy"}

	results := m.Match(content, rule)
	if len(results) == 0 {
		t.Fatal("expected at least 1 match for base64 blob")
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

	results := m.Match(content, rule)
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

	// A string with entropy between 4.0 and 4.5 — would NOT match at
	// default threshold (4.5), but SHOULD match when "password" is in the
	// line (threshold drops to 4.0).
	//
	// We'll use a carefully crafted string with known entropy.
	// "aAbBcCdDeEfFgGhH" has moderate entropy (~4.0).
	candidate := "aAbBcCdDeEfFgGhH"
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

	results := m.Match(contentNoContext, rule)
	if len(results) != 0 {
		t.Fatalf("expected 0 matches without secret context, got %d (entropy=%f)",
			len(results), entropy)
	}

	// With context ("password" on the line): should match.
	contentWithContext := []byte(`password = "` + candidate + `"` + "\n")
	results = m.Match(contentWithContext, rule)
	if len(results) == 0 {
		t.Fatalf("expected match with secret context boost (entropy=%f, boosted threshold=%f)",
			entropy, defaultEntropyThreshold-contextBoostReduction)
	}
}

func TestEntropyMatcher_ContextBoostKeywords(t *testing.T) {
	// Verify all secret hint keywords trigger the boost.
	m := &EntropyMatcher{}

	// Candidate with entropy between 4.0 and 4.5.
	candidate := "aAbBcCdDeEfFgGhH"
	entropy := ShannonEntropy(candidate)

	if entropy >= defaultEntropyThreshold || entropy < defaultEntropyThreshold-contextBoostReduction {
		t.Skipf("candidate entropy %f not in boost range; adjust test data", entropy)
	}

	for _, keyword := range secretHints {
		t.Run(keyword, func(t *testing.T) {
			content := []byte(keyword + ` = "` + candidate + `"` + "\n")
			rule := Rule{MatcherType: "entropy"}
			results := m.Match(content, rule)
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
			results := m.Match([]byte(tt.content), rule)
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

	// Use a candidate string with known entropy ~4.0 (above 3.0, below 4.5).
	candidate := "aAbBcCdDeEfFgGhH"
	entropy := ShannonEntropy(candidate)

	content := []byte(`config = "` + candidate + `"` + "\n")

	t.Run("default threshold should not match", func(t *testing.T) {
		rule := Rule{MatcherType: "entropy"}
		results := m.Match(content, rule)
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
		results := m.Match(content, rule)
		if entropy >= 3.0 && len(results) == 0 {
			t.Fatalf("expected match at threshold 3.0 for entropy %f", entropy)
		}
	})

	t.Run("raised threshold should not match", func(t *testing.T) {
		rule := Rule{
			MatcherType: "entropy",
			Metadata:    map[string]string{"entropy_threshold": "6.0"},
		}
		results := m.Match(content, rule)
		if len(results) != 0 {
			t.Fatalf("expected no match at threshold 6.0 for entropy %f", entropy)
		}
	})

	t.Run("invalid threshold falls back to default", func(t *testing.T) {
		rule := Rule{
			MatcherType: "entropy",
			Metadata:    map[string]string{"entropy_threshold": "not-a-number"},
		}
		results := m.Match(content, rule)
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

	results := m.Match(content, rule)
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

	results := m.Match(content, rule)

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

	results := m.Match(content, rule)
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
		{"base64 with symbols", "dGhpcyBpcyBhIHRl", false},
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

	results := m.Match([]byte{}, rule)
	if len(results) != 0 {
		t.Fatalf("expected 0 matches for empty content, got %d", len(results))
	}

	results = m.Match(nil, rule)
	if len(results) != 0 {
		t.Fatalf("expected 0 matches for nil content, got %d", len(results))
	}
}
